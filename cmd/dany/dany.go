// dany is a commandline DNS client that simulates (unreliable/semi-deprecated) dns `ANY`
// queries by doing individual typed DNS queries concurrently and aggregating the results

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"

	dany "github.com/gavincarr/dany/pkg"
	flags "github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
)

const dnsPort = "53"

// Options
type Options struct {
	Verbose   bool   `short:"v" long:"verbose" description:"display verbose debug output"`
	Types     string `short:"t" long:"types" description:"comma-separated list of DNS resource types to lookup (case-insensitive)"`
	Udp       bool   `          long:"udp" description:"make UDP dns queries instead of defaulting to TCP"`
	All       bool   `short:"a" long:"all" description:"display all supported DNS records (rather than default set below)"`
	Ptr       bool   `short:"p" long:"ptr" description:"lookup and append ptr records to ip results"`
	Usd       bool   `short:"u" long:"usd" description:"also lookup TXT records of well-known underscore-subdomains of domain (see below)"`
	Tag       bool   `short:"T" long:"tag" description:"tag output lines with hostname (default to true if multiple hostnames)"`
	Resolvers string `short:"r" long:"resolv" description:"text file of ip addresses to use as resolvers"`
	Server    string `short:"s" long:"server" description:"ip address of server to use as resolver"`
	Args      struct {
		Hostname  string   `description:"hostname/domain to lookup"`
		Hostname2 []string `description:"additional hostnames/domains to lookup"`
	} `positional-args:"yes"`
}

var opts Options

// Disable flags.PrintErrors for more control
var parser = flags.NewParser(&opts, flags.Default&^flags.PrintErrors)

func usage() {
	parser.WriteHelp(os.Stderr)
	fmt.Fprintf(os.Stderr, "\nDefault DNS resource types: %s\n", strings.Join(dany.DefaultRRTypes, ","))
	fmt.Fprintf(os.Stderr, "Supported DNS resource types: %s\n", strings.Join(dany.SupportedRRTypes, ","))
	fmt.Fprintf(os.Stderr, "Supported underscore-subdomains with --usd: %s\n", strings.Join(dany.SupportedUSDs, ","))
	os.Exit(2)
}

func vprintf(format string, args ...interface{}) {
	if !opts.Verbose {
		return
	}
	fmt.Fprintf(os.Stderr, "+ "+format, args...)
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

	if q.Types == nil || len(q.Types) == 0 {
		if opts.All {
			q.Types = dany.SupportedRRTypes
		} else {
			q.Types = dany.DefaultRRTypes
		}
	}

	if q.Resolvers == nil {
		config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
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
	}

	vprintf("resolvers: %v\n", q.Resolvers.List)
	vprintf("types: %v\n", q.Types)

	return q, args, nil
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

func main() {
	// Parse options
	if _, err := parser.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type != flags.ErrHelp {
			fmt.Fprintf(os.Stderr, "%s\n\n", err)
		}
		usage()
	}

	// Setup
	log.SetFlags(0)
	if opts.Args.Hostname == "" {
		usage()
	}

	// Parse options into dany.Query (including deprecated option elts in args)
	args := []string{opts.Args.Hostname}
	if len(opts.Args.Hostname2) > 0 {
		args = append(args, opts.Args.Hostname2...)
	}
	q, args, err := parseOpts(opts, args, false)
	if err != nil {
		log.Fatal(err)
	}

	// Set q.Tag to true if multiple hostnames
	if len(args) > 1 {
		q.Tag = true
	}

	// Do lookups on remaining args (sequentially across hostnames)
	for _, h := range args {
		q.Hostname = h

		if q.Server == "" || q.Resolvers.Length > 1 {
			q.Server = net.JoinHostPort(q.Resolvers.Next().String(), dnsPort)
			vprintf("server: %s\n", q.Server)
		}

		results, errors := dany.RunQuery(q)
		if results != "" {
			fmt.Fprint(os.Stdout, results)
		}
		if errors != "" {
			fmt.Fprint(os.Stderr, errors)
		}
	}
}
