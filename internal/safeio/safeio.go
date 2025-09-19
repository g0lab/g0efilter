// Package safeio provides small helpers to safely drain and close readers and to
// propagate close errors without losing earlier errors.
package safeio

import (
	"fmt"
	"io"
)

// DrainAndClose drains all data from rc to io.Discard and then closes rc.
// It returns a wrapped error if the drain or close operation fails.
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

// CloseWithErr closes c and, if dstErr is non-nil and not already set, stores
// the close error into *dstErr. This helps preserve the first error while
// ensuring resources are closed.
func CloseWithErr(dstErr *error, c io.Closer) {
	if c == nil {
		return
	}

	err := c.Close()
	if err != nil && dstErr != nil && *dstErr == nil {
		*dstErr = err
	}
}
