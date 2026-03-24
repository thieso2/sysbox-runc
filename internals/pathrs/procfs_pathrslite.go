// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (C) 2025 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2025 SUSE LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package pathrs

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/cyphar/filepath-securejoin/pathrs-lite"
	"github.com/cyphar/filepath-securejoin/pathrs-lite/procfs"
	"golang.org/x/sys/unix"
)

func procOpenReopen(openFn func(subpath string) (*os.File, error), subpath string, flags int) (*os.File, error) {
	handle, err := retryEAGAIN(func() (*os.File, error) {
		return openFn(subpath)
	})
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	f, err := Reopen(handle, flags)
	if err != nil {
		return nil, fmt.Errorf("reopen %s: %w", handle.Name(), err)
	}
	return f, nil
}

// ProcSelfOpen is a wrapper around [procfs.Handle.OpenSelf] and
// [pathrs.Reopen], to let you one-shot open a procfs file with the given
// flags.
//
// sysbox-runc: falls back to direct /proc/self open when pathrs-lite's safe
// procfs verification fails (e.g. inside a sysbox user namespace with
// FUSE-backed /proc on kernel 6.18+).
func ProcSelfOpen(subpath string, flags int) (*os.File, error) {
	proc, err := retryEAGAIN(procfs.OpenProcRoot)
	if err == nil {
		defer proc.Close()
		f, openErr := procOpenReopen(proc.OpenSelf, subpath, flags)
		if openErr == nil {
			return f, nil
		}
	}
	// Fallback: direct open through /proc/self.
	return os.OpenFile(filepath.Join("/proc/self", subpath), flags, 0)
}

// ProcPidOpen is a wrapper around [procfs.Handle.OpenPid] and [pathrs.Reopen],
// to let you one-shot open a procfs file with the given flags.
func ProcPidOpen(pid int, subpath string, flags int) (*os.File, error) {
	proc, err := retryEAGAIN(procfs.OpenProcRoot)
	if err == nil {
		defer proc.Close()
		f, openErr := procOpenReopen(func(subpath string) (*os.File, error) {
			return proc.OpenPid(pid, subpath)
		}, subpath, flags)
		if openErr == nil {
			return f, nil
		}
	}
	// Fallback: direct open through /proc/<pid>.
	return os.OpenFile(fmt.Sprintf("/proc/%d/%s", pid, subpath), flags, 0)
}

// ProcThreadSelfOpen is a wrapper around [procfs.Handle.OpenThreadSelf] and
// [pathrs.Reopen], to let you one-shot open a procfs file with the given
// flags. The returned [procfs.ProcThreadSelfCloser] needs the same handling as
// when using pathrs-lite.
//
// sysbox-runc: falls back to direct /proc/thread-self open when pathrs-lite
// fails.
func ProcThreadSelfOpen(subpath string, flags int) (_ *os.File, _ procfs.ProcThreadSelfCloser, Err error) {
	proc, err := retryEAGAIN(procfs.OpenProcRoot)
	if err == nil {
		defer proc.Close()

		handle, closer, err2 := retryEAGAIN2(func() (*os.File, procfs.ProcThreadSelfCloser, error) {
			return proc.OpenThreadSelf(subpath)
		})
		if err2 == nil {
			if closer != nil {
				defer func() {
					if Err != nil {
						closer()
					}
				}()
			}
			defer handle.Close()

			f, reopenErr := Reopen(handle, flags)
			if reopenErr == nil {
				return f, closer, nil
			}
		}
	}

	// Fallback: direct open through /proc/thread-self. We must lock the
	// OS thread so that the TID used in the path matches the thread that
	// actually opens the file descriptor.
	runtime.LockOSThread()
	tid := unix.Gettid()
	path := fmt.Sprintf("/proc/self/task/%d/%s", tid, subpath)
	f, openErr := os.OpenFile(path, flags, 0)
	if openErr != nil {
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("fallback open %s: %w (pathrs error: %v)", path, openErr, err)
	}
	closer := procfs.ProcThreadSelfCloser(func() {
		runtime.UnlockOSThread()
	})
	return f, closer, nil
}

// Reopen is a wrapper around pathrs.Reopen.
//
// sysbox-runc: falls back to direct /proc/self/fd reopen when pathrs-lite
// fails (e.g. inside sysbox's FUSE-backed /proc on kernel 6.18+).
func Reopen(file *os.File, flags int) (*os.File, error) {
	f, err := retryEAGAIN(func() (*os.File, error) {
		return pathrs.Reopen(file, flags)
	})
	if err == nil {
		return f, nil
	}
	// Fallback: reopen via /proc/self/fd/<n>.
	procPath := fmt.Sprintf("/proc/self/fd/%d", file.Fd())
	fd, procErr := unix.Open(procPath, flags, 0)
	if procErr != nil {
		return nil, fmt.Errorf("reopen %s: %w (pathrs error: %v)", file.Name(), procErr, err)
	}
	return os.NewFile(uintptr(fd), file.Name()), nil
}
