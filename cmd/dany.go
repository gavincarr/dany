// dany is a commandline DNS client that simulates (unreliable/semi-deprecated) dns `ANY`
// queries by doing individual typed DNS queries concurrently and aggregating the results

package main

import (
	"bufio"
	dany "dany/pkg"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	flags "github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
)

const dnsPort = "53"

// Options
var opts struct {
	Verbose   bool   `short:"v" long:"verbose" description:"display verbose debug output"`
	Types     string `short:"t" long:"types" description:"comma-separated list of DNS resource types to lookup (case-insensitive)"`
	All       bool   `short:"a" long:"all" description:"display all supported DNS records (rather than default set below)"`
	Ptr       bool   `short:"p" long:"ptr" description:"lookup and append ptr records to ip results"`
	Usd       bool   `short:"u" long:"usd" description:"also lookup TXT records of well-known underscore-subdomains of domain (see below)"`
	Resolvers string `short:"r" long:"resolv" description:"text file of ip addresses to use as resolvers"`
	Server    string `short:"s" long:"server" description:"ip address of server to use as resolver"`
	Args      struct {
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

type ResolverIPs []net.IP

func loadResolvers(filename string) (ResolverIPs, error) {
	fh, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	var resolvers ResolverIPs
	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		ipText := scanner.Text()
		ip := net.ParseIP(ipText)
		if ip == nil {
			err := fmt.Errorf("Error: failed to parse --resolv ip address %q", ipText)
			return nil, err
		}
		resolvers = append(resolvers, ip)
	}
	// Must have at least one resolver
	if len(resolvers) == 0 {
		err := fmt.Errorf("Error: no resolvers found in --resolv file %q", filename)
		return nil, err
	}
	return resolvers, nil
}

func (resolvers ResolverIPs) choose() net.IP {
	src := rand.NewSource(time.Now().UnixNano())
	rinst := rand.New(src)
	return resolvers[rinst.Intn(len(resolvers))]
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

func parseArgs(args []string, testMode bool) (*dany.Query, error) {
	q := new(dany.Query)
	q.NonFatal = false
	q.Ptr = opts.Ptr
	q.Usd = opts.Usd

	// Parse opts.Server
	if opts.Server != "" {
		serverIP := net.ParseIP(opts.Server)
		if serverIP == nil {
			err := fmt.Errorf("Error: unable to parse --server ip address %q", opts.Server)
			return nil, err
		}
		q.Server = net.JoinHostPort(serverIP.String(), dnsPort)
	} else if opts.Resolvers != "" {
		resolvers, err := loadResolvers(opts.Resolvers)
		if err != nil {
			return nil, err
		}
		//vprintf("resolvers: %v\n", resolvers)
		q.Server = net.JoinHostPort(resolvers.choose().String(), dnsPort)
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
			return nil, err
		}
		q.Types = types
	}

	// Regexps
	reAtPrefix := regexp.MustCompile("^@")
	reDot := regexp.MustCompile("\\.")
	reComma := regexp.MustCompile(",")

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
		if q.Hostname != "" {
			err := fmt.Errorf("Error: argument %q looks like hostname, but we already have %q",
				arg, q.Hostname)
			return nil, err
		}
		q.Hostname = arg
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
	vprintf("hostname: %s\n", q.Hostname)
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
	if opts.Args.Hostname == "" {
		usage()
	}
	// Actually treat opts.Args as an unordered []string and parse into query elements
	args := []string{opts.Args.Hostname}
	if len(opts.Args.Extra) > 0 {
		args = append(args, opts.Args.Extra...)
	}
	q, err := parseArgs(args, false)
	if err != nil {
		log.Fatal(err)
	}

	// Do lookups
	fmt.Print(dany.RunQuery(q))
}
