package secretfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadPermissionsAndBounds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  os.FileMode
		data  string
		limit int64
		valid bool
	}{
		{"owner", 0600, "secret", 6, true}, {"group_read", 0640, "secret", 6, true},
		{"group_write", 0660, "secret", 6, false}, {"world_read", 0644, "secret", 6, false},
		{"empty", 0600, "", 6, false}, {"oversize", 0600, "secret!", 6, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key")
			if err := os.WriteFile(path, []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			got, err := Read(path, tc.limit)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if tc.valid && string(got) != tc.data {
				t.Fatal("read changed bytes")
			}
		})
	}
}
func TestReadRejectsMissingDirectoryAndSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, link, filepath.Join(dir, "missing")} {
		if _, err := Read(p, 32); err == nil {
			t.Fatal("unsafe path accepted")
		}
	}
}
