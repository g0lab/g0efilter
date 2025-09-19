//nolint:testpackage // Need access to internal implementation details
package safeio

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// Test errors defined as static variables to satisfy err113 linter.
var (
	errClose         = errors.New("close failed")
	errRead          = errors.New("read failed")
	errCloseTest     = errors.New("close error")
	errExisting      = errors.New("existing error")
	errOriginalRead  = errors.New("original read error")
	errOriginalClose = errors.New("original close error")
	errPrimaryOp     = errors.New("primary operation failed")
	errCloseExample  = errors.New("close failed")
)

// mockReadCloser implements io.ReadCloser for testing.
type mockReadCloser struct {
	reader   io.Reader
	closeErr error
	closed   bool
}

func (m *mockReadCloser) Read(p []byte) (int, error) {
	if m.reader == nil {
		return 0, io.EOF
	}

	n, err := m.reader.Read(p)
	if err != nil && err != io.EOF {
		return n, fmt.Errorf("mock read: %w", err)
	}

	// io.EOF is expected behavior and should not be wrapped
	// Both return paths need explicit handling for linter compliance
	if err == io.EOF {
		return n, io.EOF
	}

	return n, nil
}

func (m *mockReadCloser) Close() error {
	m.closed = true

	return m.closeErr
}

// mockCloser implements io.Closer for testing.
type mockCloser struct {
	closeErr error
	closed   bool
}

func (m *mockCloser) Close() error {
	m.closed = true

	return m.closeErr
}

func TestDrainAndClose(t *testing.T) {
	t.Parallel()

	tests := getTestDrainAndCloseTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := DrainAndClose(tt.rc)

			if tt.expectedErr == "" {
				if err != nil {
					t.Errorf("DrainAndClose() expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("DrainAndClose() expected error %q, got nil", tt.expectedErr)
				} else if err.Error() != tt.expectedErr {
					t.Errorf("DrainAndClose() expected error %q, got %q", tt.expectedErr, err.Error())
				}
			}

			// Verify that Close was called if rc was not nil
			if tt.rc != nil {
				if mock, ok := tt.rc.(*mockReadCloser); ok {
					if !mock.closed {
						t.Error("DrainAndClose() did not close the reader")
					}
				}
			}
		})
	}
}

func getTestDrainAndCloseTests() []struct {
	name        string
	rc          io.ReadCloser
	expectedErr string
} {
	return []struct {
		name        string
		rc          io.ReadCloser
		expectedErr string
	}{
		{
			name: "nil reader closer",
			rc:   nil,
		},
		{
			name: "successful drain and close",
			rc: &mockReadCloser{
				reader: strings.NewReader("test data"),
			},
		},
		{
			name: "empty reader",
			rc: &mockReadCloser{
				reader: strings.NewReader(""),
			},
		},
		{
			name: "large data",
			rc: &mockReadCloser{
				reader: strings.NewReader(strings.Repeat("x", 10000)),
			},
		},
		{
			name: "close error only",
			rc: &mockReadCloser{
				reader:   strings.NewReader("test data"),
				closeErr: errClose,
			},
			expectedErr: "close: close failed",
		},
		{
			name: "read error with successful close",
			rc: &mockReadCloser{
				reader: &failingReader{err: errRead},
			},
			expectedErr: "drain: mock read: read failed",
		},
		{
			name: "both read and close errors",
			rc: &mockReadCloser{
				reader:   &failingReader{err: errRead},
				closeErr: errClose,
			},
			expectedErr: "drain: mock read: read failed",
		},
	}
}

func TestCloseWithErr(t *testing.T) {
	t.Parallel()

	testCloseWithErrNil(t)
	testCloseWithErrNilErrorPtr(t)
	testCloseWithErrSuccess(t)
	testCloseWithErrCloseError(t)
	testCloseWithErrExisting(t)
	testCloseWithErrPreserve(t)
}

func testCloseWithErrNil(t *testing.T) {
	t.Helper()

	t.Run("nil closer", func(t *testing.T) {
		t.Parallel()

		var err error

		CloseWithErr(&err, nil)

		if err != nil {
			t.Errorf("CloseWithErr() with nil closer should not set error, got %v", err)
		}
	})
}

func testCloseWithErrNilErrorPtr(t *testing.T) {
	t.Helper()

	t.Run("nil error pointer", func(t *testing.T) {
		t.Parallel()

		closer := &mockCloser{closeErr: errCloseTest}
		CloseWithErr(nil, closer)

		if !closer.closed {
			t.Error("CloseWithErr() should still close the closer even with nil error pointer")
		}
	})
}

func testCloseWithErrSuccess(t *testing.T) {
	t.Helper()

	t.Run("successful close with nil destination error", func(t *testing.T) {
		t.Parallel()

		var err error

		closer := &mockCloser{}
		CloseWithErr(&err, closer)

		if err != nil {
			t.Errorf("CloseWithErr() with successful close should not set error, got %v", err)
		}

		if !closer.closed {
			t.Error("CloseWithErr() should close the closer")
		}
	})
}

func testCloseWithErrCloseError(t *testing.T) {
	t.Helper()

	t.Run("close error with nil destination error", func(t *testing.T) {
		t.Parallel()

		var err error

		closer := &mockCloser{closeErr: errClose}
		CloseWithErr(&err, closer)

		if !errors.Is(err, errClose) {
			t.Errorf("CloseWithErr() expected error %v, got %v", errClose, err)
		}

		if !closer.closed {
			t.Error("CloseWithErr() should close the closer")
		}
	})
}

func testCloseWithErrExisting(t *testing.T) {
	t.Helper()

	t.Run("close error with existing destination error", func(t *testing.T) {
		t.Parallel()

		err := errExisting
		closer := &mockCloser{closeErr: errClose}
		CloseWithErr(&err, closer)

		if !errors.Is(err, errExisting) {
			t.Errorf("CloseWithErr() should preserve existing error %v, got %v", errExisting, err)
		}

		if !closer.closed {
			t.Error("CloseWithErr() should close the closer")
		}
	})
}

func testCloseWithErrPreserve(t *testing.T) {
	t.Helper()

	t.Run("successful close with existing destination error", func(t *testing.T) {
		t.Parallel()

		err := errExisting
		closer := &mockCloser{}
		CloseWithErr(&err, closer)

		if !errors.Is(err, errExisting) {
			t.Errorf("CloseWithErr() should preserve existing error %v, got %v", errExisting, err)
		}

		if !closer.closed {
			t.Error("CloseWithErr() should close the closer")
		}
	})
}

// failingReader always returns an error on Read.
type failingReader struct {
	err error
}

func (f *failingReader) Read([]byte) (int, error) {
	return 0, f.err
}

func TestDrainAndCloseErrorWrapping(t *testing.T) {
	t.Parallel()

	t.Run("drain error is wrapped", func(t *testing.T) {
		t.Parallel()

		rc := &mockReadCloser{
			reader: &failingReader{err: errOriginalRead},
		}

		err := DrainAndClose(rc)
		if err == nil {
			t.Fatal("DrainAndClose() expected error, got nil")
		}

		if !errors.Is(err, errOriginalRead) {
			t.Errorf("DrainAndClose() error should wrap original error, got %v", err)
		}

		expectedMsg := "drain: mock read: original read error"
		if err.Error() != expectedMsg {
			t.Errorf("DrainAndClose() expected error message %q, got %q", expectedMsg, err.Error())
		}
	})

	t.Run("close error is wrapped", func(t *testing.T) {
		t.Parallel()

		rc := &mockReadCloser{
			reader:   strings.NewReader("test"),
			closeErr: errOriginalClose,
		}

		err := DrainAndClose(rc)
		if err == nil {
			t.Fatal("DrainAndClose() expected error, got nil")
		}

		if !errors.Is(err, errOriginalClose) {
			t.Errorf("DrainAndClose() error should wrap original error, got %v", err)
		}

		expectedMsg := "close: original close error"
		if err.Error() != expectedMsg {
			t.Errorf("DrainAndClose() expected error message %q, got %q", expectedMsg, err.Error())
		}
	})
}

// Example usage tests to demonstrate the API.
func ExampleDrainAndClose() {
	// Simulate a reader with some data
	reader := strings.NewReader("some data to drain")
	rc := &mockReadCloser{reader: reader}

	err := DrainAndClose(rc)
	if err != nil {
		fmt.Printf("Error: %v\n", err)

		return
	}

	fmt.Println("Successfully drained and closed")
	// Output: Successfully drained and closed
}

func ExampleCloseWithErr() {
	var err = errPrimaryOp

	// We still want to close resources even if the primary operation failed
	closer := &mockCloser{}
	CloseWithErr(&err, closer)

	// The original error is preserved
	fmt.Printf("Final error: %v\n", err)
	// Output: Final error: primary operation failed
}

func ExampleCloseWithErr_preserveFirstError() {
	var err error

	// Successful primary operation (err is nil)
	// But closer fails
	closer := &mockCloser{closeErr: errCloseExample}
	CloseWithErr(&err, closer)

	// The close error is now stored in err
	fmt.Printf("Final error: %v\n", err)
	// Output: Final error: close failed
}
