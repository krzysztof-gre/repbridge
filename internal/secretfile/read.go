// Package secretfile reads bounded private files without following symlinks.
package secretfile

import (
	"fmt"
	"io"
	"os"
)

// Read checks permissions and inode identity both before and after opening.
// Group read access supports the explicitly configured nonroot Docker group.
func Read(path string, maxBytes int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o027 != 0 || info.Size() <= 0 || info.Size() > maxBytes {
		return nil, fmt.Errorf("secret must be a private, bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o027 != 0 {
		return nil, fmt.Errorf("secret file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || len(data) == 0 || int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("secret file cannot be read within its size limit")
	}
	return data, nil
}
