package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestIsSyncedFolderPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "onedrive", path: filepath.Join("C:\\Users\\alice", "OneDrive", "openclaw"), want: true},
		{name: "icloud", path: filepath.Join("/Users/alice/Library", "Mobile Documents", "com~apple~CloudDocs", "openclaw"), want: true},
		{name: "local", path: filepath.Join("/Users/alice", ".openclaw"), want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isSyncedFolderPath(test.path); got != test.want {
				t.Fatalf("isSyncedFolderPath(%q)=%v, want %v", test.path, got, test.want)
			}
		})
	}
}

func TestResolveLinkedPath(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "real-state")
	link := filepath.Join(root, "linked-state")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation unavailable on this Windows environment: %v", err)
		}
		t.Fatalf("create symlink: %v", err)
	}

	resolved, linked, err := resolveLinkedPath(link)
	if err != nil {
		t.Fatalf("resolveLinkedPath: %v", err)
	}
	if !linked {
		t.Fatalf("expected linked path to be detected")
	}
	if !pathsEqual(resolved, target) {
		t.Fatalf("resolved path = %q, want %q", resolved, target)
	}
}
