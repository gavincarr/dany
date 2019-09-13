// dany is a commandline DNS client that simulates (unreliable/semi-deprecated) dns `ANY`
// queries by doing individual typed DNS queries concurrently and aggregating the results

package main

import (
	dany "dany/pkg"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"

	flags "github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
)

const dnsPort = "53"

// Options
var opts struct {
	Verbose bool `short:"v" long:"verbose" description:"display verbose debug output"`
	All     bool `short:"a" long:"all" description:"display all supported DNS records (rather than default set below)"`
	Ptr     bool `short:"p" long:"ptr" description:"lookup and append ptr records to ip results"`
	Usd     bool `short:"u" long:"usd" description:"also lookup TXT records of well-known underscore-subdomains of domain (see below)"`
	Args    struct {
		Types    string `description:"comma-separated list of DNS resource types to lookup (case-insensitive)"`
		Hostname string `description:"hostname/domain to lookup"`
		Extra    []string
	} `positional-args:"yes"`
}

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

func parseArgs(args []string) (*dany.Query, error) {
	q := new(dany.Query)
	q.NonFatal = false
	q.Ptr = opts.Ptr

	// Regexps
	reAtPrefix := regexp.MustCompile("^@")
	reDot := regexp.MustCompile("\\.")
	reComma := regexp.MustCompile(",")

	typeMap := make(map[string]bool)
	for _, t := range dany.SupportedRRTypes {
		typeMap[t] = true
		typeMap[strings.ToLower(t)] = true
	}

	// Args: 1 domain (required); 1 @-prefixed server ip (optional); 1 comma-separated list of types (optional)
	for _, arg := range args {
		argIsRRType := false
		// Check whether non-dotted args are bare RRtypes
		if !reDot.MatchString(arg) {
			if _, ok := typeMap[arg]; ok {
				argIsRRType = true
			}
		}
		// Check for @<ip> server argument
		if reAtPrefix.MatchString(arg) {
			if q.Server != "" {
				err := fmt.Errorf("Error: argument %q looks like `@<ip>`, but we already have %q",
					arg, q.Server)
				return nil, err
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
		if argIsRRType || reComma.MatchString(arg) {
			if len(q.Types) != 0 {
				err := fmt.Errorf("Error: argument %q looks like types list, but we already have %q",
					arg, q.Types)
				return nil, err
			}
			// Check all types are valid
			types := strings.Split(arg, ",")
			var badTypes []string
			for _, t := range types {
				if _, ok := typeMap[t]; !ok {
					badTypes = append(badTypes, t)
				}
			}
			if len(badTypes) > 0 {
				err := fmt.Errorf("Error: unsupported types found in %q: %s",
					arg, strings.Join(badTypes, ","))
				return nil, err
			}
			q.Types = strings.Split(arg, ",")
			continue
		}
		// Otherwise assume hostname
		if len(q.Hostnames) >= 1 {
			err := fmt.Errorf("Error: argument %q looks like hostname, but we already have %q",
				arg, q.Hostnames[0])
			return nil, err
		}
		q.Hostnames = []string{arg}
	}

	if q.Types == nil || len(q.Types) == 0 {
		if opts.All {
			q.Types = dany.SupportedRRTypes
		} else {
			q.Types = dany.DefaultRRTypes
		}
	}

	if q.Server == "" {
		config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return nil, err
		}
		q.Server = net.JoinHostPort(config.Servers[0], config.Port)
	}

	vprintf("server: %s\n", q.Server)
	vprintf("hostname: %s\n", q.Hostnames[0])
	vprintf("types: %v\n", q.Types)

	return q, nil
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
	if opts.Args.Types == "" {
		usage()
	}
	// Actually treat opts.Args as an unordered []string and parse into query elements
	args := []string{opts.Args.Types}
	if opts.Args.Hostname != "" {
		args = append(args, opts.Args.Hostname)
	}
	if len(opts.Args.Extra) > 0 {
		args = append(args, opts.Args.Extra...)
	}
	q, err := parseArgs(args)
	if err != nil {
		log.Fatal(err)
	}

	// Do lookups
	fmt.Print(dany.RunQuery(q))
}
