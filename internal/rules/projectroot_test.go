package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveProjectRoot(t *testing.T) {
	t.Parallel()

	t.Run("relative cwd returns false", func(t *testing.T) {
		t.Parallel()
		root, ok := resolveProjectRoot("some/relative/path")
		if ok || root != "" {
			t.Fatalf("expected ('', false), got (%q, %v)", root, ok)
		}
	})

	t.Run("no .git anywhere returns false", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		sub := filepath.Join(dir, "a", "b")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		root, ok := resolveProjectRoot(sub)
		if ok || root != "" {
			t.Fatalf("expected ('', false), got (%q, %v)", root, ok)
		}
	})

	t.Run(".git directory in ancestor", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
			t.Fatal(err)
		}
		sub := filepath.Join(dir, "src", "pkg")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		root, ok := resolveProjectRoot(sub)
		if !ok {
			t.Fatal("expected ok=true")
		}
		// EvalSymlinks on TempDir may resolve symlinks (e.g. /var -> /private/var on macOS)
		wantDir, _ := filepath.EvalSymlinks(dir)
		if root != wantDir {
			t.Fatalf("expected %q, got %q", wantDir, root)
		}
	})

	t.Run(".git directory in cwd itself", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
			t.Fatal(err)
		}
		root, ok := resolveProjectRoot(dir)
		if !ok {
			t.Fatal("expected ok=true")
		}
		wantDir, _ := filepath.EvalSymlinks(dir)
		if root != wantDir {
			t.Fatalf("expected %q, got %q", wantDir, root)
		}
	})

	t.Run(".git regular file (worktree)", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ".git"), []byte("gitdir: ../.git/worktrees/foo\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		sub := filepath.Join(dir, "sub")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		root, ok := resolveProjectRoot(sub)
		if !ok {
			t.Fatal("expected ok=true for worktree file")
		}
		wantDir, _ := filepath.EvalSymlinks(dir)
		if root != wantDir {
			t.Fatalf("expected %q, got %q", wantDir, root)
		}
	})

	t.Run("cwd is symlink, walks from resolved target", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
			t.Fatal(err)
		}
		sub := filepath.Join(dir, "real")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link")
		if err := os.Symlink(sub, link); err != nil {
			t.Fatal(err)
		}
		root, ok := resolveProjectRoot(link)
		if !ok {
			t.Fatal("expected ok=true")
		}
		wantDir, _ := filepath.EvalSymlinks(dir)
		if root != wantDir {
			t.Fatalf("expected %q, got %q", wantDir, root)
		}
	})

	t.Run(".git symlink treated as marker without following", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		target := filepath.Join(dir, "dot-git-target")
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, ".git")); err != nil {
			t.Fatal(err)
		}
		root, ok := resolveProjectRoot(dir)
		if !ok {
			t.Fatal("expected ok=true for .git symlink")
		}
		wantDir, _ := filepath.EvalSymlinks(dir)
		if root != wantDir {
			t.Fatalf("expected %q, got %q", wantDir, root)
		}
	})

	t.Run("lstat error other than IsNotExist short-circuits", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		// Create a non-directory named ".git" with no-execute bit so Lstat on a
		// path *inside* it would fail, but Lstat of the entry itself succeeds.
		// Instead, simulate Lstat failure by making the parent directory
		// unreadable (no execute bit), so Lstat(".git") returns a permission error.
		sub := filepath.Join(dir, "sub")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		// Remove execute permission so Lstat of sub/.git returns permission denied.
		if err := os.Chmod(sub, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(sub, 0o755) }) //nolint:errcheck

		root, ok := resolveProjectRoot(sub)
		if ok || root != "" {
			// Restore first so TempDir cleanup works
			os.Chmod(sub, 0o755) //nolint:errcheck
			t.Fatalf("expected ('', false) on lstat error, got (%q, %v)", root, ok)
		}
		os.Chmod(sub, 0o755) //nolint:errcheck
	})
}
