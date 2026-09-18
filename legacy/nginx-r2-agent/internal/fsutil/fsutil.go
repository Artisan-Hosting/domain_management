package fsutil

import (
	"io"
	"os"
	"path/filepath"
)

func CopyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)

		if d.Type()&os.ModeSymlink != 0 {
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				return err
			}
			info, err := os.Stat(resolved)
			if err != nil {
				return err
			}
			if info.IsDir() {
				if err := CopyDir(resolved, target); err != nil {
					return err
				}
				return filepath.SkipDir
			}
			return copyFile(resolved, target)
		}

		if d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			return os.MkdirAll(target, info.Mode().Perm()|0o700)
		}
		return copyFile(path, target)
	})
}

func MirrorDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	if err := CopyDir(src, dst); err != nil {
		return err
	}
	return filepath.WalkDir(dst, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dst, path)
		if err != nil {
			return err
		}
		if _, statErr := os.Stat(filepath.Join(src, rel)); os.IsNotExist(statErr) {
			return os.Remove(path)
		}
		return nil
	})
}

func copyFile(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
