package main

import (
	"bufio"
	_ "embed"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/lmctl-ai/lmcode-go"
	"github.com/lmctl-ai/lminspect/pkg/dsl"
	"github.com/lmctl-ai/lminspect/pkg/proxy"
)

//go:embed schema/lminspect.dsl.json
var embeddedSchema []byte

var version = "0.1.0"

const usage = `usage: lminspect --version | --dsl-schema [--json] | --dsl-signatures | --dsl FILE.dslb [FILE...]
       lminspect run [--listen ADDR] [--mode MODE] [--ssl-bump] [--tap] [--record FILE] [--script FILE.dslb]
       lminspect replay --client FILE.jsonl [--target URL]
       lminspect certgen [--cert FILE] [--key FILE]`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}

	cmd := os.Args[1]
	switch cmd {
	case "--version":
		if len(os.Args) > 2 {
			fmt.Fprintln(os.Stderr, "extra argument to --version")
			os.Exit(2)
		}
		fmt.Printf("lminspect %s\n", version)
		os.Exit(0)

	case "--dsl-schema":
		// Byte-identical schema print
		_, _ = os.Stdout.Write(embeddedSchema)
		os.Exit(0)

	case "--dsl-signatures":
		host := dsl.NewHost()
		sigs := host.Registry.Signatures()
		for _, s := range sigs {
			fmt.Println(s)
		}
		os.Exit(0)

	case "--dsl":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "missing bytecode file for --dsl")
			os.Exit(2)
		}
		for _, file := range os.Args[2:] {
			code := runBytecode(file)
			if code != 0 {
				os.Exit(code)
			}
		}
		os.Exit(0)

	case "run", "proxy":
		runProxy(os.Args[2:])

	case "replay":
		runReplay(os.Args[2:])

	case "certgen":
		runCertgen(os.Args[2:])

	default:
		// If first arg looks like flags or unknown command
		if strings.HasPrefix(cmd, "-") {
			runProxy(os.Args[1:])
			return
		}
		fmt.Fprintf(os.Stderr, "unknown command: %s\n%s\n", cmd, usage)
		os.Exit(2)
	}
}

func runBytecode(filePath string) int {
	bytecode, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read bytecode file: %v\n", err)
		return 3
	}

	host := dsl.NewHost()
	prog, err := lmcode.Load(bytecode, embeddedSchema, host.Registry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load error: %v\n", err)
		return 3
	}

	ctx := lmcode.NewContext()
	ctx.Set("inspect", host.Inspector)
	if err := prog.Run(ctx, host.Registry); err != nil {
		fmt.Fprintf(os.Stderr, "run error: %v\n", err)
		return 3
	}
	fmt.Println(`{"ok": true, "result": null}`)
	return 0
}

func runProxy(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	listenAddr := fs.String("listen", "127.0.0.1:8080", "Address and port to bind proxy")
	port := fs.Int("port", 0, "Port to listen on (overrides listen port)")
	bind := fs.String("bind", "", "Bind IP address (overrides listen host)")
	mode := fs.String("mode", "regular", "Proxy mode: regular | reverse:<url> | transparent")
	sslBump := fs.Bool("ssl-bump", false, "Enable dynamic TLS decryption (MITM)")
	caCert := fs.String("ca-cert", "", "Path to custom Root CA certificate")
	caKey := fs.String("ca-key", "", "Path to custom Root CA private key")
	insecure := fs.Bool("insecure", true, "Skip TLS verification for upstream connections")
	tap := fs.Bool("tap", false, "Print real-time flow summary to stderr")
	record := fs.String("record", "", "Append transited flows to JSONL file")
	replayServer := fs.String("replay-server", "", "Serve recorded responses from JSONL file")
	script := fs.String("script", "", "Path to compiled .dslb addon script")

	// Multi-value rule flags
	var redirects stringSliceFlag
	var routes stringSliceFlag
	var headers stringSliceFlag
	var mocks stringSliceFlag
	fs.Var(&redirects, "redirect", "Redirect rule (pattern=target_url)")
	fs.Var(&routes, "route", "Route rule (pattern=host:port)")
	fs.Var(&headers, "header", "Header rule (pattern=key:val)")
	fs.Var(&mocks, "mock", "Mock response rule (pattern=code:body)")

	_ = fs.Parse(args)

	addr := *listenAddr
	if *port > 0 {
		b := "127.0.0.1"
		if *bind != "" {
			b = *bind
		}
		addr = fmt.Sprintf("%s:%d", b, *port)
	} else if *bind != "" {
		addr = fmt.Sprintf("%s:8080", *bind)
	}

	addonMgr := proxy.NewAddonManager()

	// Tap addon
	if *tap {
		addonMgr.Register(proxy.NewTapAddon(os.Stderr))
	}

	// Record addon
	if *record != "" {
		rec, err := proxy.NewRecordAddon(*record)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to initialize record addon: %v\n", err)
			os.Exit(1)
		}
		defer rec.Close()
		addonMgr.Register(rec)
	}

	// Replay server addon
	if *replayServer != "" {
		rep, err := proxy.NewReplayServerAddon(*replayServer)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load replay-server flows: %v\n", err)
			os.Exit(1)
		}
		addonMgr.Register(rep)
	}

	// Rules addon
	if len(redirects) > 0 || len(routes) > 0 || len(headers) > 0 || len(mocks) > 0 {
		rules := proxy.NewRuleAddon()
		for _, r := range redirects {
			parts := strings.SplitN(r, "=", 2)
			if len(parts) == 2 {
				_ = rules.AddRedirect(parts[0], parts[1])
			}
		}
		for _, r := range routes {
			parts := strings.SplitN(r, "=", 2)
			if len(parts) == 2 {
				_ = rules.AddRoute(parts[0], parts[1])
			}
		}
		for _, r := range headers {
			parts := strings.SplitN(r, "=", 2)
			if len(parts) == 2 {
				kv := strings.SplitN(parts[1], ":", 2)
				if len(kv) == 2 {
					_ = rules.AddHeader(parts[0], kv[0], kv[1])
				}
			}
		}
		for _, r := range mocks {
			parts := strings.SplitN(r, "=", 2)
			if len(parts) == 2 {
				cb := strings.SplitN(parts[1], ":", 2)
				if len(cb) == 2 {
					var code int
					fmt.Sscanf(cb[0], "%d", &code)
					if code == 0 {
						code = 200
					}
					_ = rules.AddMock(parts[0], code, cb[1], "text/plain")
				}
			}
		}
		addonMgr.Register(rules)
	}

	// DSL Addon
	if *script != "" {
		dslAddon, err := dsl.NewDslAddon(*script, embeddedSchema)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to initialize DSL script addon: %v\n", err)
			os.Exit(1)
		}
		addonMgr.Register(dslAddon)
	}

	server, err := proxy.NewProxyServer(proxy.ServerConfig{
		ListenAddr:         addr,
		Mode:               *mode,
		CACertPath:         *caCert,
		CAKeyPath:          *caKey,
		SSLBump:            *sslBump,
		InsecureSkipVerify: *insecure,
		Addons:             addonMgr,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "server setup error: %v\n", err)
		os.Exit(1)
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		_ = server.Shutdown(nil)
		os.Exit(0)
	}()

	fmt.Fprintf(os.Stderr, "lminspect proxy listening on %s (mode: %s, ssl-bump: %v)\n", addr, *mode, *sslBump)
	if err := server.Start(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "proxy error: %v\n", err)
		os.Exit(1)
	}
}

func runReplay(args []string) {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	clientFile := fs.String("client", "", "Replay recorded requests to target server")
	target := fs.String("target", "", "Override destination URL for replayed requests")
	_ = fs.Parse(args)

	if *clientFile == "" {
		fmt.Fprintln(os.Stderr, "usage: lminspect replay --client FILE.jsonl [--target URL]")
		os.Exit(2)
	}

	f, err := os.Open(*clientFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open replay file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	var flows []*proxy.HTTPFlow
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		fl, err := proxy.FlowFromJSON(line)
		if err == nil {
			flows = append(flows, fl)
		}
	}

	client := &http.Client{}
	success := 0
	for i, fl := range flows {
		req, err := fl.Request.ToHTTPRequest()
		if err != nil {
			continue
		}
		if *target != "" {
			req.URL.Host = *target
		}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%d/%d] REPLAY ERROR: %v\n", i+1, len(flows), err)
			continue
		}
		resp.Body.Close()
		fmt.Fprintf(os.Stderr, "[%d/%d] REPLAYED: %s %s -> %d\n", i+1, len(flows), fl.Request.Method, fl.Request.URL(), resp.StatusCode)
		success++
	}
	fmt.Fprintf(os.Stderr, "Successfully replayed %d/%d requests.\n", success, len(flows))
}

func runCertgen(args []string) {
	fs := flag.NewFlagSet("certgen", flag.ExitOnError)
	certPath := fs.String("cert", "ca.crt", "Output CA certificate path")
	keyPath := fs.String("key", "ca.key", "Output CA private key path")
	_ = fs.Parse(args)

	ca, err := proxy.NewCertAuthority(*certPath, *keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "certgen error: %v\n", err)
		os.Exit(1)
	}
	if err := ca.Save(*certPath, *keyPath); err != nil {
		fmt.Fprintf(os.Stderr, "failed to save CA: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Generated Root CA certificate at %s and key at %s\n", *certPath, *keyPath)
}

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ", ")
}

func (s *stringSliceFlag) Set(val string) error {
	*s = append(*s, val)
	return nil
}
