package libcontainer

import (
	stderrors "errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReopenExecFifoUsesSecureReopenWhenAvailable(t *testing.T) {
	handle, err := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open handle: %v", err)
	}
	defer handle.Close()

	want, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open expected file: %v", err)
	}
	defer want.Close()

	oldReopen := execFifoReopen
	execFifoReopen = func(file *os.File, flags int) (*os.File, error) {
		if file != handle {
			t.Fatalf("reopen called with unexpected file: got %p want %p", file, handle)
		}
		if flags != unix.O_WRONLY|unix.O_CLOEXEC {
			t.Fatalf("reopen called with unexpected flags: got %#x", flags)
		}
		return want, nil
	}
	defer func() {
		execFifoReopen = oldReopen
	}()

	got, err := reopenExecFifo(handle)
	if err != nil {
		t.Fatalf("reopen exec fifo: %v", err)
	}
	if got != want {
		t.Fatalf("reopen exec fifo returned unexpected file: got %p want %p", got, want)
	}
}

func TestReopenExecFifoFallsBackToProcSelfFd(t *testing.T) {
	fifoPath := filepath.Join(t.TempDir(), "exec.fifo")
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	readerFd, err := unix.Open(fifoPath, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open fifo reader: %v", err)
	}
	reader := os.NewFile(uintptr(readerFd), fifoPath)
	defer reader.Close()

	handleFd, err := unix.Open(fifoPath, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open fifo handle: %v", err)
	}
	handle := os.NewFile(uintptr(handleFd), "initfifo")
	defer handle.Close()

	oldReopen := execFifoReopen
	execFifoReopen = func(file *os.File, flags int) (*os.File, error) {
		if file != handle {
			t.Fatalf("reopen called with unexpected file: got %p want %p", file, handle)
		}
		if flags != unix.O_WRONLY|unix.O_CLOEXEC {
			t.Fatalf("reopen called with unexpected flags: got %#x", flags)
		}
		return nil, stderrors.New("pathrs reopen failed")
	}
	defer func() {
		execFifoReopen = oldReopen
	}()

	writer, err := reopenExecFifo(handle)
	if err != nil {
		t.Fatalf("reopen exec fifo fallback: %v", err)
	}
	defer writer.Close()

	if _, err := writer.Write([]byte("0")); err != nil {
		t.Fatalf("write fifo: %v", err)
	}

	buf := make([]byte, 1)
	n, err := reader.Read(buf)
	if err != nil {
		t.Fatalf("read fifo: %v", err)
	}
	if n != 1 || buf[0] != '0' {
		t.Fatalf("unexpected fifo payload: n=%d buf=%q", n, buf[:n])
	}
}
