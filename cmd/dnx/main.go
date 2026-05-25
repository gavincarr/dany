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

	"github.com/gavincarr/dany"
	"github.com/gavincarr/dany/internal/version"
	flags "github.com/jessevdk/go-flags"
	"github.com/lmittmann/tint"
	"github.com/miekg/dns"
)

const name = "dnx"

// dnsPort is the port appended to resolver IPs. Declared as a var (not
// const) so end-to-end tests can point runCLI at testdns's random port.
var dnsPort = "53"

// Options
type Options struct {
	Verbose     []bool `short:"v" long:"verbose" description:"verbose output (-v: info, -vv: debug)"`
	Resolvers   string `short:"r" long:"resolv" description:"text file of ip addresses to use as resolvers"`
	Server      string `short:"s" long:"server" description:"ip address of server to use as resolver"`
	Concurrency int    `short:"C" long:"concurrency" description:"number of hostnames to query concurrently per resolver" default:"3"`
	Count       bool   `short:"c" long:"count" description:"report all domains and a count of non-NXDOMAIN responses, comma-separated"`
	Invert      bool   `short:"V" long:"invert" description:"report domains that do NOT return NXDOMAIN"`
	Types       string `short:"t" long:"types" description:"comma-separated DNS types to probe for NX detection (default: MX,NS,SOA)"`
	Version     bool   `          long:"version" description:"print version and exit"`
	Args        struct {
		Hostname  string   `description:"hostname/domain to lookup"`
		Hostname2 []string `description:"additional hostnames/domains to lookup"`
	} `positional-args:"yes"`
}

func usage(parser *flags.Parser) {
	parser.WriteHelp(os.Stderr)
	fmt.Fprintf(os.Stderr, "\nDefault NX-probe types: %s\n", strings.Join(dany.NXTypes, ","))
	fmt.Fprintf(os.Stderr, "Supported DNS resource types: %s\n", strings.Join(dany.SupportedRRTypes, ","))
	os.Exit(2)
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
	setupLogger(len(opts.Verbose))
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
	// Disable flags.PrintErrors for more control
	parser := flags.NewParser(&opts, flags.Default&^flags.PrintErrors)

	if _, err := parser.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type != flags.ErrHelp {
			fmt.Fprintf(os.Stderr, "%s\n\n", err)
		}
		usage(parser)
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
