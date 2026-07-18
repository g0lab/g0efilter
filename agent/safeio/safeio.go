// Package safeio provides helpers to safely drain and close readers.
package safeio

import (
	"fmt"
	"io"
)

// DrainAndClose drains all data from rc and then closes it.
func DrainAndClose(rc io.ReadCloser) error {
	if rc == nil {
		return nil
	}

	_, copyErr := io.Copy(io.Discard, rc)

	closeErr := rc.Close()

	if copyErr != nil {
		return fmt.Errorf("drain: %w", copyErr)
	}

	if closeErr != nil {
		return fmt.Errorf("close: %w", closeErr)
	}

	return nil
}

// CloseWithErr closes c and stores close error in *dstErr if not already set.
func CloseWithErr(dstErr *error, c io.Closer) {
	if c == nil {
		return
	}

	err := c.Close()
	if err != nil && dstErr != nil && *dstErr == nil {
		*dstErr = err
	}
}
