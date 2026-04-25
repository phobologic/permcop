package rules

import (
	"os"
	"path/filepath"
)

// resolveProjectRoot walks upward from cwd to find the nearest ancestor that
// contains a .git entry (directory or regular file). A regular-file .git is a
// git worktree pointer and is treated as a valid root marker without reading
// its contents.
//
// Deliberate divergence from internal/config/loader.go:196 FindLayers, which
// only IsDir-checks .git as a stop boundary and ignores worktree files.
// Unification is out of scope for this epic.
func resolveProjectRoot(cwd string) (string, bool) {
	if !filepath.IsAbs(cwd) {
		return "", false
	}

	resolved, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		return "", false
	}

	dir := filepath.Clean(resolved)
	for {
		_, err := os.Lstat(filepath.Join(dir, ".git"))
		if err == nil {
			return dir, true
		}
		if !os.IsNotExist(err) {
			return "", false
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}
