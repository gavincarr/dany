// dany is a commandline DNS client that simulates (unreliable/semi-deprecated) dns `ANY`
// queries by doing individual typed DNS queries concurrently and aggregating the results

package main

import (
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/gavincarr/dany"
	"github.com/gavincarr/dany/internal/version"
	helpcolours "github.com/gavincarr/kong-help-colours"
	"github.com/lmittmann/tint"
	"github.com/miekg/dns"
)

const (
	fallbackServer = "8.8.8.8"
	resolvConfPath = "/etc/resolv.conf"
	name           = "dany"
)

// dnsPort is the port appended to resolver IPs. Declared as a var (not
// const) so end-to-end tests can point runCLI at testdns's random port.
var dnsPort = "53"

// Options
type Options struct {
	Verbose   int    `short:"v" type:"counter" help:"verbose output (-v: info, -vv: debug)"`
	Types     string `short:"t" help:"comma-separated list of DNS resource types to lookup (case-insensitive)"`
	Udp       bool   `help:"make UDP dns queries instead of defaulting to TCP"`
	All       bool   `short:"a" help:"display all supported DNS records (rather than default set below)"`
	Ptr       bool   `short:"p" help:"lookup and append ptr records to ip results"`
	Usd       bool   `short:"u" help:"also lookup TXT records of well-known underscore-subdomains of domain (see below)"`
	Www       bool   `short:"w" help:"also lookup A/AAAA records for www.<hostname>"`
	Tag       bool   `short:"T" help:"tag output lines with hostname (text format only; default to true if multiple hostnames)"`
	Fmt       string `short:"f" enum:"text,json,yaml,yml" default:"text" help:"output format (one of: ${enum})"`
	Output    string `short:"o" help:"write output to <path> instead of stdout (truncates; appends across multiple hostnames within one invocation)"`
	Version   bool   `help:"print version and exit"`
	Resolvers string `short:"r" name:"resolv" help:"text file of ip addresses to use as resolvers"`
	Server    string `short:"s" help:"ip address of server to use as resolver"`
	Args      struct {
		Hostname  string   `arg:"" optional:"" help:"hostname/domain to lookup"`
		Hostname2 []string `arg:"" optional:"" name:"hostname2" help:"additional hostnames/domains to lookup"`
	} `embed:""`
}

// writeTypesFooter prints the runtime-derived list of default/supported RR
// types and USD subdomains. Lives outside the flag struct because the lists
// are sourced from the dany library at runtime.
func writeTypesFooter(w io.Writer) {
	fmt.Fprintf(w, "\nDefault DNS resource types: %s\n", strings.Join(dany.DefaultRRTypes, ","))
	fmt.Fprintf(w, "Supported DNS resource types: %s\n", strings.Join(dany.SupportedRRTypes, ","))
	fmt.Fprintf(w, "Supported underscore-subdomains with --usd: %s\n", strings.Join(dany.SupportedUSDs, ","))
	fmt.Fprintf(w, "  (a name that exists without records — e.g. _domainkey when DKIM selectors are present — is reported as \"[present; no records]\")\n")
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
// (silent for everything dany currently logs). TimeFormat is a single
// space because dany runs in well under a second; per-line timestamps
// are noise.
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

// Check all types exist in typeMaps - if not, return an error itemising those that don't
func checkValidTypes(types []string, typeMap map[string]bool) error {
	var badTypes []string
	for _, t := range types {
		if _, ok := typeMap[t]; !ok {
			badTypes = append(badTypes, t)
		}
	}
	if len(badTypes) > 0 {
		err := fmt.Errorf("Error: unsupported types found in %q: %s",
			strings.Join(types, ","), strings.Join(badTypes, ","))
		return err
	}
	return nil
}

// Parse options and arguments and return a dany.Query object and a list of (real) arguments
func parseOpts(opts Options, args []string, testMode bool) (*dany.Query, []string, error) {
	q := new(dany.Query)
	q.Udp = opts.Udp
	q.Ptr = opts.Ptr
	q.Usd = opts.Usd
	q.Www = opts.Www
	q.Tag = opts.Tag

	// Parse opts.Server
	if opts.Server != "" {
		serverIP := net.ParseIP(opts.Server)
		if serverIP == nil {
			err := fmt.Errorf("Error: unable to parse --server ip address %q", opts.Server)
			return nil, nil, err
		}
		q.Resolvers = dany.NewResolvers(serverIP)
	} else if opts.Resolvers != "" {
		resolvers, err := dany.LoadResolvers(opts.Resolvers)
		if err != nil {
			return nil, nil, err
		}
		q.Resolvers = resolvers
	}

	// Parse opts.Types
	typeMap := make(map[string]bool)
	for _, t := range dany.SupportedRRTypes {
		typeMap[t] = true
		typeMap[strings.ToLower(t)] = true
	}
	if opts.Types != "" {
		types := strings.Split(opts.Types, ",")
		err := checkValidTypes(types, typeMap)
		if err != nil {
			return nil, nil, err
		}
		q.Types = types
	}

	args, err := parseArgs(q, args, typeMap, testMode)
	if err != nil {
		return nil, nil, err
	}

	// Track whether the user made an explicit type choice (-t, -a, or
	// the deprecated bare-types positional arg) before defaults kick in.
	// Used below to decide whether --www should mirror that set or fall
	// back to its address-only default.
	typesExplicit := len(q.Types) > 0 || opts.All

	if q.Types == nil || len(q.Types) == 0 {
		if opts.All {
			q.Types = dany.SupportedRRTypes
		} else {
			q.Types = dany.DefaultRRTypes
		}
	}

	if typesExplicit {
		q.WwwTypes = q.Types
	}

	//
	// /etc/resolv.conf won't exist on Windows.  In that case, fall back to
	// some well-known server, like Google's 8.8.8.8 or CloudFlare's 1.1.1.1.
	//
	// In theory, we can figure out what the default DNS server for the
	// current machine is by using e.g.
	//
	// https://github.com/qdm12/dns/blob/v2.0.0-beta/pkg/nameserver/getlocal_windows.go
	//
	// but it's really not worth the trouble, because it pulls in a ton of
	// other dependencies we don't really need.
	//
	if q.Resolvers == nil && readable(resolvConfPath) {
		config, err := dns.ClientConfigFromFile(resolvConfPath)
		if err != nil {
			return nil, nil, err
		}
		for _, server := range config.Servers {
			serverIP := net.ParseIP(server)
			if serverIP == nil {
				err := fmt.Errorf("Error: unable to parse --server ip address %q", opts.Server)
				return nil, nil, err
			}
			if q.Resolvers == nil {
				q.Resolvers = dany.NewResolvers(serverIP)
			} else {
				q.Resolvers.Append(serverIP)
			}
		}
	} else if q.Resolvers == nil {
		q.Resolvers = dany.NewResolvers(net.ParseIP(fallbackServer))
	}

	slog.Info("resolvers configured", "resolvers", q.Resolvers.List)
	slog.Info("types configured", "types", q.Types)

	return q, args, nil
}

// Readable returns true if the specified path is readable (file exists, permissions are OK, etc)
func readable(path string) bool {
	_, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return true
}

// Types and Server args are deprecated, but for now we have to keep checking for them
func parseArgs(q *dany.Query, args []string, typeMap map[string]bool, testMode bool) ([]string, error) {
	// Regexps
	reAtPrefix := regexp.MustCompile("^@")
	reDot := regexp.MustCompile("\\.")
	reComma := regexp.MustCompile(",")

	// Args: 1 domain (required); 1 @-prefixed server ip (optional); 1 comma-separated list of types (optional)
	var newargs []string
	for _, arg := range args {
		argIsRRType := false
		// Check whether non-dotted args are bare RRtypes
		if !reDot.MatchString(arg) {
			if _, ok := typeMap[arg]; ok {
				argIsRRType = true
			}
		}
		// Check for @<ip> server argument
		// Deprecated: use -s <ip> option instead
		if reAtPrefix.MatchString(arg) {
			if q.Server != "" {
				err := fmt.Errorf("Error: argument %q looks like `@<ip>`, but we already have %q",
					arg, q.Server)
				return nil, err
			}
			if !testMode {
				// Deprecation warning
				fmt.Fprintln(os.Stderr, "Warning: the @<ip> server argument is deprecated and will be removed in a future release")
				fmt.Fprintln(os.Stderr, "Please use the '-s/--server <ip>' option instead")
			}
			serverIP := net.ParseIP(arg[1:])
			if serverIP == nil {
				err := fmt.Errorf("Error: argument %q looks like `@<ip>`, but unable to parse ip address",
					arg)
				return nil, err
			}
			q.Server = net.JoinHostPort(serverIP.String(), dnsPort)
			continue
		}
		// Check for <RR>[,<RR>...] types argument
		// Deprecated: use -t <types> option instead
		if argIsRRType || reComma.MatchString(arg) {
			if len(q.Types) != 0 {
				err := fmt.Errorf("Error: argument %q looks like types list, but we already have %q",
					arg, q.Types)
				return nil, err
			}
			if !testMode {
				// Deprecation warning
				fmt.Fprintln(os.Stderr, "Warning: the [Types] argument is deprecated and will be removed in a future release")
				fmt.Fprintln(os.Stderr, "Please use the '-t/--types <types>' option instead")
			}
			// Check all types are valid
			types := strings.Split(arg, ",")
			err := checkValidTypes(types, typeMap)
			if err != nil {
				return nil, err
			}
			q.Types = types
			continue
		}
		// Otherwise assume hostname
		newargs = append(newargs, arg)
	}

	return newargs, nil
}

// nopCloser lets openOutput return a uniform io.Closer for the stdout
// path so callers can always `defer closer.Close()` without nil-checking.
type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// openOutput resolves the -o/--output target. Empty path → defaultOut with
// a no-op closer; non-empty → os.Create (truncating) returning the file as
// both writer and closer. Threading defaultOut (rather than hard-coding
// os.Stdout) lets runCLI's caller hand in a *bytes.Buffer for tests.
func openOutput(path string, defaultOut io.Writer) (io.Writer, io.Closer, error) {
	if path == "" {
		return defaultOut, nopCloser{}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, f, nil
}

// runCLI is the testable entry point: turns Options into a dany.Query, runs
// the lookups, and writes rendered output to out. -o/--output overrides
// out; per-error stderr writes (text mode) still go to os.Stderr.
func runCLI(opts Options, out io.Writer) error {
	setupLogger(opts.Verbose)
	log.SetFlags(0)

	args := []string{opts.Args.Hostname}
	if len(opts.Args.Hostname2) > 0 {
		args = append(args, opts.Args.Hostname2...)
	}
	q, args, err := parseOpts(opts, args, false)
	if err != nil {
		return err
	}

	if len(args) > 1 {
		q.Tag = true
	}

	// -o/--output truncates on open and is reused across hostnames so
	// multi-host runs land in one file (NDJSON-style for -f json, multi-doc
	// YAML for -f yaml, just concatenated for text).
	out, closer, err := openOutput(opts.Output, out)
	if err != nil {
		return err
	}
	defer closer.Close()

	for _, h := range args {
		q.Hostname = h

		if q.Server == "" || q.Resolvers.Length > 1 {
			q.Server = net.JoinHostPort(q.Resolvers.Next().String(), dnsPort)
			slog.Info("resolver selected", "server", q.Server)
		}

		answers, errs := dany.RunQuery(q)
		switch opts.Fmt {
		case "json":
			// Errors fold into the JSON envelope; nothing goes to stderr.
			fmt.Fprint(out, dany.RenderJSON(answers, q, errs))
		case "yaml", "yml":
			fmt.Fprint(out, dany.RenderYAML(answers, q, errs))
		default:
			if rendered := dany.Render(answers, q.Tag); rendered != "" {
				fmt.Fprint(out, rendered)
			}
			for _, e := range errs {
				fmt.Fprintln(os.Stderr, e)
			}
		}
	}
	return nil
}

func main() {
	var opts Options
	parser, err := kong.New(&opts,
		kong.Name(name),
		kong.Description("dany simulates DNS ANY queries by querying multiple types concurrently and aggregating the results."),
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
	// validation (so e.g. `dany --version` works without a hostname).
	if opts.Version {
		fmt.Printf("%s %s\n", name, version.Version)
		return
	}

	if opts.Args.Hostname == "" {
		fmt.Fprintf(os.Stderr, "Error: hostname/domain required. Run `%s --help` for usage.\n", name)
		writeTypesFooter(os.Stderr)
		os.Exit(2)
	}

	if err := runCLI(opts, os.Stdout); err != nil {
		log.Fatal(err)
	}
}
