package certpublish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"nginx-r2-agent/internal/fsutil"
	"nginx-r2-agent/internal/r2sync"
)

type Config struct {
	Bucket           string
	Prefix           string
	SourceTree       string
	CertIssuerScript string
	WorkRoot         string
	KeepStage        bool
	DoIssueCerts     bool
	DoPublish        bool
	Interval         time.Duration
}

type manifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type manifest struct {
	ReleaseID   string         `json:"release_id"`
	CreatedUnix int64          `json:"created_unix"`
	Platform    string         `json:"platform"`
	FileCount   int            `json:"file_count"`
	Files       []manifestFile `json:"files"`
}

func logf(format string, args ...any) {
	log.Printf("[issuer] "+format, args...)
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
	if _, err := os.Stat(cfg.SourceTree); err != nil {
		return fmt.Errorf("source tree missing: %s", cfg.SourceTree)
	}
	if cfg.DoIssueCerts {
		if _, err := os.Stat(cfg.CertIssuerScript); err != nil {
			return fmt.Errorf("cert issuer script missing: %s", cfg.CertIssuerScript)
		}
	}

	releaseID := time.Now().UTC().Format("2006-01-02T15-04-05Z")
	stageDir := filepath.Join(cfg.WorkRoot, "stage", releaseID)
	stageTree := filepath.Join(stageDir, "tree")
	manifestPath := filepath.Join(stageDir, "manifest.json")

	if err := os.MkdirAll(stageTree, 0o755); err != nil {
		return err
	}
	defer func() {
		if !cfg.KeepStage {
			_ = os.RemoveAll(stageDir)
		} else {
			logf("keeping staged directory: %s", stageDir)
		}
	}()

	logf("release id: %s", releaseID)

	if cfg.DoIssueCerts {
		logf("running cert issuer script: %s", cfg.CertIssuerScript)
		cmd := exec.CommandContext(ctx, "bash", cfg.CertIssuerScript)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("cert issuer script failed: %w", err)
		}
	} else {
		logf("skipping issuance (DoIssueCerts=false)")
	}

	logf("snapshotting %s -> %s", cfg.SourceTree, stageTree)
	if err := fsutil.MirrorDir(cfg.SourceTree, stageTree); err != nil {
		return fmt.Errorf("snapshotting source tree: %w", err)
	}

	logf("testing nginx config (attempt A: nginx -t -p stageTree -c nginx.conf)")
	testA := exec.CommandContext(ctx, "/sbin/nginx", "-t", "-p", stageTree, "-c", "nginx.conf")
	testA.Stdout, testA.Stderr = os.Stdout, os.Stderr
	if err := testA.Run(); err != nil {
		logf("attempt A failed, falling back to sandbox clone test")
		sandboxEtc := filepath.Join(stageDir, "sandbox", "etc", "nginx")
		if err := fsutil.MirrorDir(stageTree, sandboxEtc); err != nil {
			return fmt.Errorf("building sandbox: %w", err)
		}
		testB := exec.CommandContext(ctx, "/sbin/nginx", "-t", "-c", filepath.Join(sandboxEtc, "nginx.conf"))
		testB.Stdout, testB.Stderr = os.Stdout, os.Stderr
		if err := testB.Run(); err != nil {
			return fmt.Errorf("nginx config test failed in sandbox: %w", err)
		}
	}
	logf("nginx config test: OK")

	logf("writing manifest: %s", manifestPath)
	if err := writeManifest(stageTree, releaseID, manifestPath); err != nil {
		return fmt.Errorf("writing manifest: %w", err)
	}

	if !cfg.DoPublish {
		logf("skipping publish (DoPublish=false); local stage at %s", stageDir)
		return nil
	}

	releasePrefix := fmt.Sprintf("%s/releases/%s", cfg.Prefix, releaseID)
	logf("uploading tree -> %s/tree", releasePrefix)
	if err := cl.UploadTree(ctx, stageTree, releasePrefix+"/tree"); err != nil {
		return fmt.Errorf("uploading tree: %w", err)
	}

	logf("uploading manifest -> %s/manifest.json", releasePrefix)
	if err := cl.PutFile(ctx, releasePrefix+"/manifest.json", manifestPath); err != nil {
		return fmt.Errorf("uploading manifest: %w", err)
	}

	logf("updating latest pointer -> %s/latest", cfg.Prefix)
	if err := cl.PutObjectString(ctx, cfg.Prefix+"/latest", releaseID); err != nil {
		return fmt.Errorf("updating latest pointer: %w", err)
	}

	logf("publish complete: %s", releaseID)
	return nil
}

func writeManifest(treeDir, releaseID, manifestPath string) error {
	var files []manifestFile
	err := filepath.WalkDir(treeDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(treeDir, path)
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		h := sha256.New()
		size, err := io.Copy(h, f)
		if err != nil {
			return err
		}
		files = append(files, manifestFile{
			Path:   filepath.ToSlash(rel),
			SHA256: hex.EncodeToString(h.Sum(nil)),
			Bytes:  size,
		})
		return nil
	})
	if err != nil {
		return err
	}

	m := manifest{
		ReleaseID:   releaseID,
		CreatedUnix: time.Now().Unix(),
		Platform:    runtime.GOOS + "/" + runtime.GOARCH,
		FileCount:   len(files),
		Files:       files,
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(manifestPath, b, 0o644)
}
