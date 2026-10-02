// dishnet-vpnd is the DishNet Secure Connect management service: device API,
// administrator dashboard and WireGuard/nftables provisioner for the hub.
//
// Subcommands:
//
//	serve              run the service (default)
//	admin-create       create an administrator account
//	render-firewall    print the nftables rules the current database implies (no changes made)
//	reconcile-once     converge the hub once and exit
//
// All configuration is by environment variable (see Config) so the systemd
// unit is the single place it lives.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/dishnetafrica/wiregaurd/server/internal/admin"
	"github.com/dishnetafrica/wiregaurd/server/internal/api"
	"github.com/dishnetafrica/wiregaurd/server/internal/auth"
	"github.com/dishnetafrica/wiregaurd/server/internal/firewall"
	"github.com/dishnetafrica/wiregaurd/server/internal/provision"
	"github.com/dishnetafrica/wiregaurd/server/internal/store"
	"github.com/dishnetafrica/wiregaurd/server/internal/wg"
)

type Config struct {
	DBPath        string        // DISHNET_DB            default /var/lib/dishnet/dishnet.db
	Listen        string        // DISHNET_LISTEN        default 127.0.0.1:8080 (Caddy terminates TLS in front)
	Interface     string        // DISHNET_WG_INTERFACE  default wg0
	Endpoint      string        // DISHNET_WG_ENDPOINT   default 165.227.89.92:51820
	PoolCIDR      string        // DISHNET_POOL          default 10.20.0.0/24
	PoolBlockLen  int           // DISHNET_POOL_BLOCK    default 28
	HubAddresses  string        // DISHNET_HUB_ADDRS     default 10.20.0.1
	NFTFile       string        // DISHNET_NFT_FILE      default /etc/nftables.d/dishnet.nft
	AdminAllow    string        // DISHNET_ADMIN_ALLOW   comma-separated CIDRs; empty = any
	TrustProxy    bool          // DISHNET_TRUST_PROXY   true when behind Caddy on localhost
	DryRun        bool          // DISHNET_DRY_RUN       use fake backends (development / staging on a laptop)
	Reconcile     time.Duration // DISHNET_RECONCILE     default 60s
	InsecureCooks bool          // DISHNET_INSECURE_COOKIES only for dry-run over plain http
	PublicURL     string        // DISHNET_PUBLIC_URL     default https://vpn.dishnetuganda.com (install links)
	InstallerPath string        // DISHNET_INSTALLER_PATH default /var/lib/dishnet/installer/DishNetSecureConnect-Setup.exe
	NotifyWebhook string        // DISHNET_NOTIFY_WEBHOOK optional URL that receives JSON for new trial requests
	SupportText   string        // DISHNET_SUPPORT_CONTACT shown on public pages, e.g. "WhatsApp 0705 993 348"
}

func loadConfig() Config {
	get := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	blockLen, _ := strconv.Atoi(get("DISHNET_POOL_BLOCK", "28"))
	rec, _ := time.ParseDuration(get("DISHNET_RECONCILE", "60s"))
	return Config{
		DBPath: get("DISHNET_DB", "/var/lib/dishnet/dishnet.db"), Listen: get("DISHNET_LISTEN", "127.0.0.1:8080"),
		Interface: get("DISHNET_WG_INTERFACE", "wg0"), Endpoint: get("DISHNET_WG_ENDPOINT", "165.227.89.92:51820"),
		PoolCIDR: get("DISHNET_POOL", "10.20.0.0/24"), PoolBlockLen: blockLen, HubAddresses: get("DISHNET_HUB_ADDRS", "10.20.0.1"),
		NFTFile: get("DISHNET_NFT_FILE", "/etc/nftables.d/dishnet.nft"), AdminAllow: os.Getenv("DISHNET_ADMIN_ALLOW"),
		TrustProxy: get("DISHNET_TRUST_PROXY", "true") == "true", DryRun: os.Getenv("DISHNET_DRY_RUN") == "true",
		Reconcile: rec, InsecureCooks: os.Getenv("DISHNET_INSECURE_COOKIES") == "true",
		PublicURL: get("DISHNET_PUBLIC_URL", "https://vpn.dishnetuganda.com"), InstallerPath: get("DISHNET_INSTALLER_PATH", "/var/lib/dishnet/installer/DishNetSecureConnect-Setup.exe"),
		NotifyWebhook: os.Getenv("DISHNET_NOTIFY_WEBHOOK"), SupportText: os.Getenv("DISHNET_SUPPORT_CONTACT"),
	}
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := loadConfig()
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(cfg, log)
	case "admin-create":
		err = adminCreate(cfg, os.Args[2:])
	case "render-firewall":
		err = renderFirewall(cfg, log)
	case "reconcile-once":
		err = reconcileOnce(cfg, log)
	case "version":
		fmt.Println("dishnet-vpnd", version)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

var version = "dev"

func buildService(cfg Config, log *slog.Logger) (*provision.Service, error) {
	db, err := store.Open(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	var backend wg.Backend
	var fw firewall.Applier
	var router provision.Router
	if cfg.DryRun {
		log.Warn("DRY RUN: using fake WireGuard/nftables backends; nothing on this machine is changed")
		fake := wg.NewFake()
		if k := os.Getenv("DISHNET_HUB_PUBLIC_KEY"); k != "" {
			fake.Key = k
		}
		backend, fw, router = fake, &firewall.Fake{}, &provision.FakeRouter{}
	} else {
		backend = &wg.Kernel{Interface: cfg.Interface}
		fw = &firewall.NFT{Path: cfg.NFTFile}
		router = provision.IPRoute{}
	}
	var hubAddrs []netip.Addr
	for _, s := range strings.Split(cfg.HubAddresses, ",") {
		if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
			hubAddrs = append(hubAddrs, a)
		}
	}
	svc := provision.New(provision.Config{Interface: cfg.Interface, Endpoint: cfg.Endpoint, HubAddresses: hubAddrs, VPNPool: cfg.PoolCIDR, SupportContact: cfg.SupportText}, db, backend, fw, router, log)
	pool, err := netip.ParsePrefix(cfg.PoolCIDR)
	if err != nil {
		return nil, fmt.Errorf("DISHNET_POOL: %w", err)
	}
	if err := svc.EnsurePool(context.Background(), "primary", pool, cfg.PoolBlockLen); err != nil {
		return nil, err
	}
	return svc, nil
}

func serve(cfg Config, log *slog.Logger) error {
	svc, err := buildService(cfg, log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Converge before accepting requests, so a restart never serves configs
	// for peers that are not on the hub yet.
	if err := svc.Reconcile(ctx); err != nil {
		log.Error("initial reconcile failed; continuing, will retry", "err", err)
	}
	go svc.RunReconciler(ctx, cfg.Reconcile)

	var allow []netip.Prefix
	for _, s := range strings.Split(cfg.AdminAllow, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			if a, err2 := netip.ParseAddr(s); err2 == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			} else {
				return fmt.Errorf("DISHNET_ADMIN_ALLOW: bad entry %q", s)
			}
		}
		allow = append(allow, p)
	}
	if len(allow) == 0 {
		log.Warn("DISHNET_ADMIN_ALLOW is empty: the dashboard is reachable from any address (still password protected)")
	}
	adminH, err := admin.New(svc, log, admin.Options{Allowlist: allow, TrustProxy: cfg.TrustProxy, SecureCookies: !cfg.InsecureCooks, PublicURL: cfg.PublicURL})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	api.New(svc, log, cfg.TrustProxy).Register(mux)
	api.NewDownloads(svc, cfg.InstallerPath, log).Register(mux)
	api.NewTrialPages(svc, cfg.SupportText).Register(mux)
	api.NewUpdates(cfg.InstallerPath, cfg.PublicURL).Register(mux)
	api.RegisterManual(mux)
	if cfg.NotifyWebhook != "" {
		svc.SetNotifier(&provision.WebhookNotifier{URL: cfg.NotifyWebhook})
	}
	adminH.Register(mux)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/admin", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})
	srv := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Info("dishnet-vpnd listening", "addr", cfg.Listen, "interface", cfg.Interface, "dry_run", cfg.DryRun, "version", version)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func adminCreate(cfg Config, args []string) error {
	if len(args) < 2 {
		return errors.New("usage: dishnet-vpnd admin-create <email> <owner|operator|viewer>   (password read from DISHNET_ADMIN_PASSWORD or prompted)")
	}
	role, ok := store.ParseAdminRole(args[1])
	if !ok {
		return errors.New("role must be owner, operator or viewer")
	}
	password := os.Getenv("DISHNET_ADMIN_PASSWORD")
	if password == "" {
		fmt.Fprint(os.Stderr, "Password (min 12 chars): ")
		if term.IsTerminal(int(os.Stdin.Fd())) {
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return err
			}
			password = string(b)
		} else {
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			password = strings.TrimRight(line, "\r\n")
		}
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	db, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Tx(context.Background(), func(tx *store.Tx) error {
		a, err := tx.InsertAdmin(store.Admin{Email: args[0], PasswordHash: hash, Role: role})
		if err != nil {
			return err
		}
		fmt.Printf("created administrator %s (%s)\n", a.Email, a.Role)
		return tx.Audit(store.AuditEntry{ActorType: "system", ActorID: "cli", Action: "admin.create", Target: a.Email, Detail: string(role)})
	})
}

func renderFirewall(cfg Config, log *slog.Logger) error {
	cfg.DryRun = true
	svc, err := buildService(cfg, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	if err != nil {
		return err
	}
	desired, err := svc.Desired(context.Background())
	if err != nil {
		return err
	}
	var hubAddrs []netip.Addr
	for _, s := range strings.Split(cfg.HubAddresses, ",") {
		if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
			hubAddrs = append(hubAddrs, a)
		}
	}
	out, err := firewall.Render(firewall.Spec{Interface: cfg.Interface, Rules: desired.Rules, HubAddresses: hubAddrs})
	if err != nil {
		return err
	}
	fmt.Print(out)
	fmt.Fprintf(os.Stderr, "# %d peers, %d rules, %d routes\n", len(desired.Peers), len(desired.Rules), len(desired.Routes))
	return nil
}

func reconcileOnce(cfg Config, log *slog.Logger) error {
	svc, err := buildService(cfg, log)
	if err != nil {
		return err
	}
	return svc.Reconcile(context.Background())
}
