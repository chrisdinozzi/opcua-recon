// This line declares which "package" this file belongs to.
// In Go, a program that you can run must have a package called "main".
// (Libraries you import have other names, like "opcua" or "fmt".)
package main

// The import block lists the other packages this file uses.
// Standard-library packages are single words ("fmt", "os").
// Third-party ones are full paths that look like URLs ("github.com/...").
// Go is strict: if you import something and don't use it, it won't compile.
import (
	"context" // for timeouts/cancellation — passed into network calls
	"flag"    // parses command-line flags like -endpoint
	"fmt"     // formatted printing (Println, Printf, etc.)
	"os"      // access to os.Stderr and os.Exit for error handling
	"sort"    // to sort the list of auth methods alphabetically
	"time"    // for time.Second when building the timeout

	// The gopcua library, split into two packages we need:
	"github.com/fatih/color"
	"github.com/gopcua/opcua"    // the client + GetEndpoints entry points
	"github.com/gopcua/opcua/ua" // the OPC-UA type definitions (enums, structs)
)

const banner = `
                                                                                
  ####  #####   ####        #    #   ##      #####  ######  ####   ####  #    # 
 #    # #    # #    #       #    #  #  #     #    # #      #    # #    # ##   # 
 #    # #    # #      ##### #    # #    #    #    # #####  #      #    # # #  # 
 #    # #####  #            #    # ######    #####  #      #      #    # #  # # 
 #    # #      #    #       #    # #    #    #   #  #      #    # #    # #   ## 
  ####  #       ####         ####  #    #    #    # ######  ####   ####  #    # 
`

// "func main()" is the entry point. When you run the program, Go calls this.
// The empty () means it takes no arguments; no return type means it returns nothing.
func main() {
	fmt.Println(banner)

	// flag.String defines a string command-line flag.
	//   arg 1: the flag name, so "-endpoint" on the command line
	//   arg 2: the default value if the user doesn't pass it
	//   arg 3: the help text shown by -h
	// It returns a *pointer* to a string (that's what the * means in the type).
	// We'll dereference it later with *endpoint to read the actual value.
	endpoint := flag.String("endpoint", "opc.tcp://localhost:4840", "OPC-UA endpoint URL")
	ip := flag.String("ip", "0.0.0.0", "OPC-UA server IP")
	port := flag.Int("port", 4840, "OPC-UA server port. Default 4840")
	// A bool flag. Present ("-probe") = true, absent = false.
	probe := flag.Bool("probe", false, "also actively test whether anonymous login truly works")

	// This actually parses os.Args and fills in the variables above.
	// Nothing is populated until Parse() runs.
	flag.Parse()

	if ip != nil {
		url := fmt.Sprintf("opc.tcp://%s:%d", *ip, *port)
		endpoint = &url

	}

	color.Blue("Target: ", *endpoint)

	// ":=" is Go's "declare and assign" operator — it creates a new variable
	// and infers its type from the right-hand side. (You'd use "=" to assign
	// to an already-declared variable.)
	//
	// A context carries a deadline. context.WithTimeout returns two things:
	// the context itself, and a "cancel" function you must call to release
	// its resources. Go functions can return multiple values — that's the
	// (ctx, cancel) on the left.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	// "defer" schedules a function call to run when the surrounding function
	// (main) returns, no matter how it exits. It's Go's cleanup mechanism —
	// like a finally block. Here it guarantees we release the context.
	defer cancel()

	scanServer(ctx, endpoint, probe)

}

func scanServer(ctx context.Context, endpoint *string, probe *bool) {
	// Call GetEndpoints. It returns two values: the result, and an error.
	// This "value, err := call()" pattern is *everywhere* in Go — Go doesn't
	// use exceptions; functions return an error value you're expected to check.
	//
	// GetEndpoints runs the pre-auth discovery handshake (HEL/ACK -> OPN(None)
	// -> GetEndpoints) under the hood and gives back the advertised endpoints.
	endpoints, err := opcua.GetEndpoints(ctx, *endpoint)

	// The idiomatic error check: "if err is not nil, something went wrong."
	// nil is Go's null/none. If GetEndpoints succeeded, err is nil.
	if err != nil {
		// Fprintf prints to a given writer — here os.Stderr (the error stream)
		// rather than normal output. %v is a general-purpose "print any value"
		// verb; \n is a newline.
		fmt.Fprintf(os.Stderr, "GetEndpoints failed: %v\n", err)
		// os.Exit(1) quits immediately with exit code 1 (non-zero = failure).
		os.Exit(1)
	}

	// Printf with format verbs: %s inserts a string, %d inserts an integer.
	// len(endpoints) gives the number of items in the slice (Go's dynamic array).
	fmt.Printf("=== %s ===\n%d endpoint(s)\n\n", *endpoint, len(endpoints))

	// Plain bool variables, both starting false. We'll flip them as we discover
	// what kinds of authentication the server advertises.
	anyAnonymous := false
	anyCredential := false

	// A "map" is Go's hash table / dictionary. map[string]bool means
	// "keys are strings, values are bools". make() allocates an empty one.
	// We use it as a set: presence of a key means "we saw this method".
	seen := make(map[string]bool)

	// "for ... range" iterates over a slice. It yields two values each loop:
	// the index (i) and a copy of the element (ep). Since we want both here,
	// we take both.
	for i, ep := range endpoints {
		// i is 0-based, so i+1 makes the display start at 1.
		fmt.Printf("[Endpoint %d]\n", i+1)

		// ep is an *ua.EndpointDescription. The dot accesses its fields.
		// EndpointURL, SecurityMode, etc. are fields defined by the library.
		fmt.Printf("  URL:             %s\n", ep.EndpointURL)

		// SecurityMode is an enum type that knows how to print itself as text
		// (the library gives it a String() method), so %s shows "None"/"Sign"/etc.
		fmt.Printf("  Security mode:   %s\n", ep.SecurityMode)

		// We pass the long policy URI through our helper (defined below) to
		// trim it to just the readable tail.
		fmt.Printf("  Security policy: %s\n", shortPolicy(ep.SecurityPolicyURI))
		fmt.Printf("  Security level:  %d\n", ep.SecurityLevel)

		// Declare a slice of strings with no initial contents (its zero value
		// is nil, which append handles fine). We'll collect method names here.
		var methods []string

		// Loop over the endpoint's accepted authentication policies.
		// We only care about the value, not the index, so we use "_" for the
		// index — "_" is Go's throwaway/blank identifier for values you ignore.
		for _, tok := range ep.UserIdentityTokens {
			// Convert the numeric token-type enum into a readable label.
			name := tokenTypeName(tok.TokenType)

			// append adds to a slice and returns the (possibly resized) slice,
			// which we assign back. Slices don't grow in place; this is the
			// standard append-and-reassign idiom.
			methods = append(methods, name)

			// Record the method name in our set.
			seen[name] = true

			// A "switch" on the token type. Unlike C, Go's switch cases don't
			// fall through by default — each case stands alone, no "break" needed.
			switch tok.TokenType {
			case ua.UserTokenTypeAnonymous:
				// Anonymous = guest access is on offer.
				anyAnonymous = true
			case ua.UserTokenTypeUserName,
				ua.UserTokenTypeCertificate,
				ua.UserTokenTypeIssuedToken:
				// A single case can list multiple values separated by commas.
				// Any of these means real credentials are needed.
				anyCredential = true
			}
		}

		// If the endpoint advertised no methods at all, show a placeholder.
		// len() on a slice is its length; 0 means empty.
		if len(methods) == 0 {
			// A one-element slice literal: []string{ ...items... }.
			methods = []string{"(none advertised)"}
		}

		// %v prints the whole slice, e.g. [Anonymous (guest)].
		fmt.Printf("  Auth methods:    %v\n\n", methods)
	}

	// Print the summary verdict.
	fmt.Println("---")

	// A "switch" with no expression after it acts like an if/else-if chain:
	// each case is a boolean condition, and the first true one runs.
	switch {
	case anyAnonymous && anyCredential:
		// && is logical AND.
		color.Yellow("VERDICT: guest access is available (some endpoints also accept/require credentials).")
	case anyAnonymous:
		color.Red("VERDICT: GUEST ACCESS — server advertises Anonymous authentication.")
	case anyCredential:
		color.Green("VERDICT: CREDENTIALS REQUIRED — no anonymous endpoint advertised.")
	default:
		// default runs if no case matched (like "else").
		fmt.Println("VERDICT: no user identity tokens advertised (unusual — check manually).")
	}

	// Turn the "seen" set (a map) into a sorted slice for tidy printing.
	// make([]string, 0, len(seen)) creates an empty slice but pre-reserves
	// capacity for len(seen) items — a small efficiency, not required.
	methods := make([]string, 0, len(seen))

	// Ranging over a map yields key, value. We only want the keys (the method
	// names), so we ignore the value with "_".
	for m := range seen {
		methods = append(methods, m)
	}
	// Sort the slice in place, alphabetically.
	sort.Strings(methods)
	fmt.Printf("Auth methods across all endpoints: %v\n", methods)

	// *probe dereferences the bool pointer from the flag. If -probe was passed,
	// run the active confirmation step.
	if *probe {
		// Call our probe helper, passing the context and the endpoint value.
		runAnonymousProbe(ctx, *endpoint)
	}
}

// ---------------------------------------------------------------------------
// Helper functions live outside main(). Go doesn't care about definition order
// within a package — main() above can call these even though they're below it.
// ---------------------------------------------------------------------------

// runAnonymousProbe actively opens an anonymous session to confirm whether
// guest access truly works (advertising it and honouring it can differ).
//
// The parameter list "(ctx context.Context, endpoint string)" names each
// argument and its type. This function returns nothing.
func runAnonymousProbe(ctx context.Context, endpoint string) {
	fmt.Println("\n--- active anonymous probe ---")

	// opcua.NewClient builds a client configured for anonymous auth.
	// opcua.AuthAnonymous() is an "option" — gopcua uses the functional-options
	// pattern where you pass configuration as function calls. Returns (client, error).
	c, err := opcua.NewClient(endpoint, opcua.AuthAnonymous())
	if err != nil {
		fmt.Printf("could not build client: %v\n", err)
		return // exit this function early (main continues)
	}

	// Connect performs the full handshake AND opens+activates a session.
	// If anonymous access is genuinely allowed, this returns nil.
	// If the server rejects the anonymous identity, err is non-nil.
	if err := c.Connect(ctx); err != nil {
		// Note: you can declare a variable *inside* the if (err := ...);
		// it's then scoped to just this if/else. Common Go idiom.
		color.Green("RESULT: anonymous login REJECTED (%v)\n", err)
		return
	}

	// If we reach here, the session opened. defer the disconnect so it always
	// runs when this function returns, keeping the session from lingering.
	defer c.Close(ctx)

	color.Red("RESULT: anonymous login SUCCEEDED — guest access genuinely works.")
}

// tokenTypeName maps the numeric UserTokenType enum to a human label.
// It takes a ua.UserTokenType and returns a string (the "string" after the
// parameters is the return type).
func tokenTypeName(t ua.UserTokenType) string {
	switch t {
	case ua.UserTokenTypeAnonymous:
		return "Anonymous (guest)"
	case ua.UserTokenTypeUserName:
		return "Username/Password"
	case ua.UserTokenTypeCertificate:
		return "X.509 Certificate"
	case ua.UserTokenTypeIssuedToken:
		return "Issued Token"
	default:
		// Sprintf builds a string instead of printing it. %d formats the
		// numeric enum value so unknown types still show something useful.
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

// shortPolicy trims a long SecurityPolicy URI down to the part after the '#'.
// e.g. "http://opcfoundation.org/UA/SecurityPolicy#None" -> "None".
func shortPolicy(uri string) string {
	// Walk backwards from the end of the string looking for '#'.
	// len(uri)-1 is the last index; i-- decrements each iteration.
	for i := len(uri) - 1; i >= 0; i-- {
		// Strings are indexed as bytes; a single-quote literal like '#' is a
		// byte (rune) constant. If this byte is '#', return everything after it.
		if uri[i] == '#' {
			// uri[i+1:] is a "slice expression": from index i+1 to the end.
			return uri[i+1:]
		}
	}
	// If we never found a '#': empty string gets a placeholder, otherwise
	// return the URI unchanged.
	if uri == "" {
		return "(none)"
	}
	return uri
}
