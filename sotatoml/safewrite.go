package sotatoml

import (
	"fmt"
	"os"
)

// SafeWrite performs an atomic write to the file which ensures:
// * Safe concurrent reads of the file.
// * Power-safe file operations.
func SafeWrite(name string, data []byte) error {
	tmpfile := name + ".tmp"
	f, err := os.OpenFile(tmpfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return fmt.Errorf("Unable to create %s: %w", name, err)
	}
	defer os.Remove(tmpfile)
	_, err = f.Write(data)
	if err1 := f.Sync(); err1 != nil && err == nil {
		err = err1
	}
	if err1 := f.Close(); err1 != nil && err == nil {
		err = err1
	}

	if err != nil {
		return fmt.Errorf("Unable to create %s: %w", name, err)
	}
	return os.Rename(tmpfile, name)
}
