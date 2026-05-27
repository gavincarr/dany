// dnx is a commandline DNS client for processing multiple hostnames
// (as arguments or on stdin) and reporting those that return NXDOMAIN
// on dns lookups. For safety, dnx does multiple typed lookups
// concurrently and only reports those that fail all tests.

package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/alecthomas/kong"
	"github.com/gavincarr/dany"
	"github.com/gavincarr/dany/internal/version"
	helpcolours "github.com/gavincarr/kong-help-colours"
	"github.com/lmittmann/tint"
	"github.com/miekg/dns"
)

const name = "dnx"

// dnsPort is the port appended to resolver IPs. Declared as a var (not
// const) so end-to-end tests can point runCLI at testdns's random port.
var dnsPort = "53"

// Options
type Options struct {
	Verbose     int    `short:"v" type:"counter" help:"verbose output (-v: info, -vv: debug)"`
	Resolvers   string `short:"r" name:"resolv" help:"text file of ip addresses to use as resolvers"`
	Server      string `short:"s" help:"ip address of server to use as resolver"`
	Concurrency int    `short:"C" default:"3" help:"number of hostnames to query concurrently per resolver"`
	Count       bool   `short:"c" help:"report all domains and a count of non-NXDOMAIN responses, comma-separated"`
	Invert      bool   `short:"V" help:"report domains that do NOT return NXDOMAIN"`
	Types       string `short:"t" help:"comma-separated DNS types to probe for NX detection (default: MX,NS,SOA)"`
	Version     bool   `help:"print version and exit"`
	Args        struct {
		Hostname  string   `arg:"" optional:"" help:"hostname/domain to lookup"`
		Hostname2 []string `arg:"" optional:"" name:"hostname2" help:"additional hostnames/domains to lookup"`
	} `embed:""`
}

// writeTypesFooter prints the runtime-derived list of NX-probe and supported
// RR types. Lives outside the flag struct because the lists are sourced from
// the dany library at runtime.
func writeTypesFooter(w io.Writer) {
	fmt.Fprintf(w, "\nDefault NX-probe types: %s\n", strings.Join(dany.NXTypes, ","))
	fmt.Fprintf(w, "Supported DNS resource types: %s\n", strings.Join(dany.SupportedRRTypes, ","))
}

// helpEpilog hooks Kong's --help path to append writeTypesFooter after the
// standard help block.
func helpEpilog(options kong.HelpOptions, ctx *kong.Context) error {
	if err := helpcolours.Help(options, ctx); err != nil {
		return err
	}
	writeTypesFooter(ctx.Stdout)
	return nil
}

// setupLogger installs a tint-colored slog handler on stderr at a level
// derived from the -v count: bare -v → Info, -vv → Debug, none → Warn
// (silent for everything dnx currently logs). TimeFormat is a single
// space because dnx runs short and per-line timestamps are noise.
func setupLogger(verbosity int) {
	level := slog.LevelWarn
	switch {
	case verbosity >= 2:
		level = slog.LevelDebug
	case verbosity >= 1:
		level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(tint.NewHandler(os.Stderr, &tint.Options{
		Level:      level,
		TimeFormat: " ",
	})))
}

// Parse options and return a set of resolvers and the list of types to probe
// (nil/empty means: let dany.RunNXQuery fall back to dany.NXTypes).
func parseOpts(opts Options) (*dany.Resolvers, []string, error) {
	var resolvers *dany.Resolvers
	var types []string
	var err error

	if opts.Types != "" {
		typeMap := make(map[string]bool)
		for _, t := range dany.SupportedRRTypes {
			typeMap[t] = true
			typeMap[strings.ToLower(t)] = true
		}
		types = strings.Split(opts.Types, ",")
		var bad []string
		for _, t := range types {
			if !typeMap[t] {
				bad = append(bad, t)
			}
		}
		if len(bad) > 0 {
			return nil, nil, fmt.Errorf("Error: unsupported types in %q: %s",
				opts.Types, strings.Join(bad, ","))
		}
	}

	if opts.Server != "" {
		// Parse opts.Server
		serverIP := net.ParseIP(opts.Server)
		if serverIP == nil {
			err = fmt.Errorf("Error: unable to parse --server ip address %q", opts.Server)
			return nil, nil, err
		}
		resolvers = dany.NewResolvers(serverIP)
	} else if opts.Resolvers != "" {
		// Parse opts.Resolvers
		resolvers, err = dany.LoadResolvers(opts.Resolvers)
		if err != nil {
			return nil, nil, err
		}
	} else {
		// No Server or Resolvers option set - use /etc/resolv.conf
		config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return nil, nil, err
		}
		for _, server := range config.Servers {
			serverIP := net.ParseIP(server)
			if serverIP == nil {
				err = fmt.Errorf("Error: unable to parse --server ip address %q", opts.Server)
				return nil, nil, err
			}
			if resolvers == nil {
				resolvers = dany.NewResolvers(serverIP)
			} else {
				resolvers.Append(serverIP)
			}
		}
	}

	slog.Info("resolvers configured", "resolvers", resolvers.List)
	if len(types) > 0 {
		slog.Info("types configured", "types", types)
	}

	return resolvers, types, nil
}

// runCLI is the testable entry point: parses opts, fans out NX probes
// across goroutines, and writes hostname lines to out. Writes from
// goroutines are serialized so out can be a *bytes.Buffer in tests.
func runCLI(opts Options, out io.Writer) error {
	setupLogger(opts.Verbose)
	log.SetFlags(0)

	resolvers, types, err := parseOpts(opts)
	if err != nil {
		return err
	}

	// out is shared across goroutines; serialize so a *bytes.Buffer (test)
	// or a redirected stdout doesn't interleave lines.
	var mu sync.Mutex
	emit := func(format string, args ...interface{}) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(out, format, args...)
	}

	concurrency := opts.Concurrency * resolvers.Length
	sem := make(chan bool, concurrency)

	process := func(hostname string) {
		defer func() { <-sem }()

		server := net.JoinHostPort(resolvers.Next().String(), dnsPort)
		slog.Debug("looking up hostname", "hostname", hostname, "server", server)
		responseCount := dany.RunNXQuery(&dany.Query{Hostname: hostname, Server: server, Types: types})
		if opts.Count {
			emit("%s,%d\n", hostname, responseCount)
			return
		}
		nxdomain := responseCount == 0
		if opts.Invert {
			nxdomain = !nxdomain
		}
		if nxdomain {
			emit("%s\n", hostname)
		}
	}

	if opts.Args.Hostname != "" {
		args := []string{opts.Args.Hostname}
		if len(opts.Args.Hostname2) > 0 {
			args = append(args, opts.Args.Hostname2...)
		}
		for _, hostname := range args {
			sem <- true
			go process(hostname)
		}
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			hostname := scanner.Text()
			sem <- true
			go process(hostname)
		}
	}
	// Wait for remaining goroutines by refilling all sem slots
	for i := 0; i < cap(sem); i++ {
		sem <- true
	}
	return nil
}

func main() {
	var opts Options
	parser, err := kong.New(&opts,
		kong.Name(name),
		kong.Description("dnx reports hostnames whose DNS lookups return NXDOMAIN for every probed type."),
		kong.UsageOnError(),
		kong.Help(helpEpilog),
	)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := parser.Parse(os.Args[1:]); err != nil {
		parser.FatalIfErrorf(err)
	}

	// --version is a short-circuit: print and exit before any further
	// validation (so e.g. `dnx --version` works without arguments).
	if opts.Version {
		fmt.Printf("%s %s\n", name, version.Version)
		return
	}

	if err := runCLI(opts, os.Stdout); err != nil {
		log.Fatal(err)
	}
}
