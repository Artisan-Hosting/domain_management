package nginxsync

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"nginx-r2-agent/internal/fsutil"
	"nginx-r2-agent/internal/r2sync"
)

type Config struct {
	Bucket       string
	Prefix       string
	SyncRoot     string
	EtcNginx     string
	Mode         string
	PartialPaths []string
	KeepBackups  int
	Interval     time.Duration
}

func logf(format string, args ...any) {
	log.Printf("[proxy] "+format, args...)
}

func RunLoop(ctx context.Context, cl *r2sync.Client, cfg Config) {
	runOnceLogged(ctx, cl, cfg)
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			logf("shutting down")
			return
		case <-ticker.C:
			runOnceLogged(ctx, cl, cfg)
		}
	}
}

func runOnceLogged(ctx context.Context, cl *r2sync.Client, cfg Config) {
	if err := RunOnce(ctx, cl, cfg); err != nil {
		logf("ERROR: %v", err)
	}
}

func RunOnce(ctx context.Context, cl *r2sync.Client, cfg Config) error {
	if err := os.MkdirAll(filepath.Join(cfg.SyncRoot, "stage"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(cfg.SyncRoot, "backup"), 0o755); err != nil {
		return err
	}
	stateDir := filepath.Join(cfg.SyncRoot, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return err
	}
	latestFile := filepath.Join(stateDir, "latest_applied")

	releaseID, err := cl.GetObjectString(ctx, cfg.Prefix+"/latest")
	if err != nil {
		return fmt.Errorf("reading latest pointer: %w", err)
	}
	if releaseID == "" {
		return fmt.Errorf("empty release id from %s/latest", cfg.Prefix)
	}

	if applied, err := os.ReadFile(latestFile); err == nil {
		if string(applied) == releaseID {
			logf("already on latest release (%s); nothing to do", releaseID)
			return nil
		}
	}

	stageDir := filepath.Join(cfg.SyncRoot, "stage", releaseID)
	treeDir := filepath.Join(stageDir, "tree")
	backupDir := filepath.Join(cfg.SyncRoot, "backup", time.Now().UTC().Format("2006-01-02T15-04-05Z"))

	logf("latest release: %s", releaseID)
	logf("downloading release tree from R2")
	if err := cl.DownloadTree(ctx, fmt.Sprintf("%s/releases/%s/tree", cfg.Prefix, releaseID), treeDir); err != nil {
		return fmt.Errorf("downloading tree: %w", err)
	}

	logf("backing up %s -> %s", cfg.EtcNginx, backupDir)
	if err := fsutil.CopyDir(cfg.EtcNginx, backupDir); err != nil {
		return fmt.Errorf("backing up nginx config: %w", err)
	}

	if cfg.Mode == "full" {
		logf("applying FULL tree to %s", cfg.EtcNginx)
		if err := fsutil.MirrorDir(treeDir, cfg.EtcNginx); err != nil {
			return fmt.Errorf("applying tree: %w", err)
		}
	} else {
		logf("applying PARTIAL paths to %s", cfg.EtcNginx)
		for _, p := range cfg.PartialPaths {
			src := filepath.Join(treeDir, p)
			if _, err := os.Stat(src); os.IsNotExist(err) {
				logf("  - skipping %s (not present in release tree)", p)
				continue
			}
			logf("  - syncing %s", p)
			if err := fsutil.MirrorDir(src, filepath.Join(cfg.EtcNginx, p)); err != nil {
				return fmt.Errorf("applying %s: %w", p, err)
			}
		}
	}

	logf("testing nginx config")
	if err := exec.Command("/usr/sbin/nginx", "-t").Run(); err != nil {
		logf("ERROR: nginx -t failed, rolling back to %s", backupDir)
		if rbErr := fsutil.MirrorDir(backupDir, cfg.EtcNginx); rbErr != nil {
			logf("ERROR: rollback copy failed: %v", rbErr)
		}
		if tErr := exec.Command("/usr/sbin/nginx", "-t").Run(); tErr == nil {
			_ = exec.Command("systemctl", "reload", "nginx").Run()
		}
		return fmt.Errorf("nginx -t failed on new config: %w", err)
	}

	logf("reloading nginx")
	if err := exec.Command("systemctl", "reload", "nginx").Run(); err != nil {
		return fmt.Errorf("reloading nginx: %w", err)
	}

	if err := os.WriteFile(latestFile, []byte(releaseID), 0o644); err != nil {
		return fmt.Errorf("recording applied release: %w", err)
	}
	logf("OK: applied release %s", releaseID)

	pruneStageDirs(filepath.Join(cfg.SyncRoot, "stage"), releaseID)
	pruneBackups(filepath.Join(cfg.SyncRoot, "backup"), cfg.KeepBackups)
	return nil
}

func pruneStageDirs(stageRoot, keep string) {
	entries, err := os.ReadDir(stageRoot)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() && e.Name() != keep {
			_ = os.RemoveAll(filepath.Join(stageRoot, e.Name()))
		}
	}
}

func pruneBackups(backupRoot string, keep int) {
	if keep <= 0 {
		return
	}
	entries, err := os.ReadDir(backupRoot)
	if err != nil {
		return
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	if len(names) <= keep {
		return
	}
	for _, n := range names[keep:] {
		_ = os.RemoveAll(filepath.Join(backupRoot, n))
	}
}
