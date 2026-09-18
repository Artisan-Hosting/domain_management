package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"nginx-r2-agent/internal/certpublish"
	"nginx-r2-agent/internal/nginxsync"
	"nginx-r2-agent/internal/r2sync"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	mode := os.Args[1]

	fs := flag.NewFlagSet(mode, flag.ExitOnError)
	once := fs.Bool("once", false, "run a single iteration and exit instead of looping forever")
	_ = fs.Parse(os.Args[2:])

	endpoint := requireEnv("R2_ENDPOINT")
	bucket := envOr("R2_BUCKET", "certificate-bucket-1")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cl, err := r2sync.New(ctx, endpoint, bucket)
	if err != nil {
		log.Fatalf("setting up R2 client: %v", err)
	}

	switch mode {
	case "sync":
		cfg := nginxsync.Config{
			Bucket:       bucket,
			Prefix:       envOr("R2_PREFIX", "nginx"),
			SyncRoot:     envOr("SYNC_ROOT", "/var/lib/nginx-sync"),
			EtcNginx:     envOr("ETC_NGINX", "/etc/nginx"),
			Mode:         envOr("MODE", "full"),
			PartialPaths: splitCSV(envOr("PARTIAL_PATHS", "sites-enabled,snippets,certs,streams-enabled")),
			KeepBackups:  envOrInt("KEEP_BACKUPS", 10),
			Interval:     envOrDuration("SYNC_INTERVAL", 30*time.Second),
		}
		if *once {
			if err := nginxsync.RunOnce(ctx, cl, cfg); err != nil {
				log.Fatalf("[proxy] %v", err)
			}
			return
		}
		nginxsync.RunLoop(ctx, cl, cfg)

	case "publish":
		cfg := certpublish.Config{
			Bucket:           bucket,
			Prefix:           envOr("R2_PREFIX", "nginx"),
			SourceTree:       envOr("SOURCE_TREE", "/mnt/nginx_local"),
			CertIssuerScript: envOr("CERT_ISSUER_SCRIPT", "/usr/local/bin/certs"),
			WorkRoot:         envOr("WORK_ROOT", "/opt/nginx-publisher"),
			KeepStage:        envOrBool("KEEP_STAGE", false),
			DoIssueCerts:     envOrBool("DO_ISSUE_CERTS", true),
			DoPublish:        envOrBool("DO_PUBLISH", true),
			Interval:         envOrDuration("PUBLISH_INTERVAL", 12*time.Hour),
		}
		if *once {
			if err := certpublish.RunOnce(ctx, cl, cfg); err != nil {
				log.Fatalf("[issuer] %v", err)
			}
			return
		}
		certpublish.RunLoop(ctx, cl, cfg)

	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: nginx-r2-agent <sync|publish> [--once]")
}

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("missing required env var %s", key)
	}
	return v
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envOrBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envOrDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
