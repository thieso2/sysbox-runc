//
// Copyright 2019-2020 Nestybox, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package sysbox

import (
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"

	"github.com/nestybox/sysbox-ipc/sysboxFsGrpc"
	"github.com/nestybox/sysbox-ipc/sysboxMgrGrpc"
	sh "github.com/nestybox/sysbox-libs/idShiftUtils"
	linuxUtils "github.com/nestybox/sysbox-libs/linuxUtils"
	libutils "github.com/nestybox/sysbox-libs/utils"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/urfave/cli"
)

// runDir holds the sysbox runtime directory. It defaults to "/run/sysbox"
// but can be overridden via --run-dir on the CLI or the SYSBOX_RUN_DIR env var.
// Precedence: --run-dir flag > SYSBOX_RUN_DIR env var > default.
//
// Both sources are resolved in init() by scanning os.Args and os.Getenv,
// bypassing urfave/cli v1 entirely. This is necessary because urfave/cli v1's
// context.GlobalString does not reliably return global flag values when called
// from app.Before with a subcommand present (e.g., "sysbox-runc --run-dir /x create ...").
var runDir = "/run/sysbox"

func init() {
	// CLI flag takes highest precedence — scan os.Args directly because
	// init() runs before urfave/cli parses anything.
	for i, arg := range os.Args[1:] {
		if arg == "--run-dir" || arg == "-run-dir" {
			if i+1 < len(os.Args)-1 {
				SetRunDir(os.Args[i+2])
				return
			}
		}
		if strings.HasPrefix(arg, "--run-dir=") {
			SetRunDir(strings.TrimPrefix(arg, "--run-dir="))
			return
		}
		if strings.HasPrefix(arg, "-run-dir=") {
			SetRunDir(strings.TrimPrefix(arg, "-run-dir="))
			return
		}
	}
	// Fall back to env var.
	if dir := os.Getenv("SYSBOX_RUN_DIR"); dir != "" {
		SetRunDir(dir)
	}
}

// SetRunDir overrides the sysbox runtime directory and updates gRPC socket addresses.
// It also sets the SYSBOX_RUN_DIR env var so that re-exec'd child processes
// (e.g., "sysbox-runc init") inherit the value.
func SetRunDir(dir string) {
	runDir = dir
	os.Setenv("SYSBOX_RUN_DIR", dir)
	sysboxMgrGrpc.SetSockAddr(path.Join(dir, "sysmgr.sock"))
	sysboxFsGrpc.SetSockAddr(path.Join(dir, "sysfs.sock"))
}

// Holds sysbox-specific config
type Sysbox struct {
	Id                  string
	Mgr                 *Mgr
	Fs                  *Fs
	RootfsUidShiftType  sh.IDShiftType
	BindMntUidShiftType sh.IDShiftType
	RootfsCloned        bool
	SwitchDockerDns     bool
	OrigRootfs          string
	OrigMounts          []specs.Mount
	IDshiftIgnoreList   []string
}

func NewSysbox(id string, withMgr, withFs bool) *Sysbox {

	sysMgr := NewMgr(id, withMgr)
	sysFs := NewFs(id, withFs)

	return &Sysbox{
		Id:  id,
		Mgr: sysMgr,
		Fs:  sysFs,
	}
}

func checkKernelVersion(distro string) error {
	var (
		reqMaj, reqMin int
		major, minor   int
	)

	rel, err := linuxUtils.GetKernelRelease()
	if err != nil {
		return err
	}

	major, minor, err = linuxUtils.ParseKernelRelease(rel)
	if err != nil {
		return err
	}

	if distro == "ubuntu" {
		reqMaj = minKernelUbuntu.major
		reqMin = minKernelUbuntu.minor
	} else {
		reqMaj = minKernel.major
		reqMin = minKernel.minor
	}

	supported := false
	if major > reqMaj {
		supported = true
	} else if major == reqMaj {
		if minor >= reqMin {
			supported = true
		}
	}

	if !supported {
		s := []string{strconv.Itoa(reqMaj), strconv.Itoa(reqMin)}
		kver := strings.Join(s, ".")
		return fmt.Errorf("%s kernel release %v is not supported; need >= %v", distro, rel, kver)
	}

	return nil
}

// needUidShiftOnRootfs checks if uid/gid shifting is required on the container's rootfs.
func needUidShiftOnRootfs(spec *specs.Spec) (bool, error) {
	var hostUidMap, hostGidMap uint32

	// the uid map is assumed to be present
	for _, mapping := range spec.Linux.UIDMappings {
		if mapping.ContainerID == 0 {
			hostUidMap = mapping.HostID
			break
		}
	}

	// the gid map is assumed to be present
	for _, mapping := range spec.Linux.GIDMappings {
		if mapping.ContainerID == 0 {
			hostGidMap = mapping.HostID
			break
		}
	}

	// find the rootfs owner
	rootfs := spec.Root.Path

	fi, err := os.Stat(rootfs)
	if err != nil {
		return false, err
	}

	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("failed to convert to syscall.Stat_t")
	}

	rootfsUid := st.Uid
	rootfsGid := st.Gid

	// Use shifting when the rootfs is owned by true root and the containers uid/gid root
	// mapping don't match the container's rootfs owner.
	if rootfsUid == 0 && rootfsGid == 0 &&
		hostUidMap != rootfsUid && hostGidMap != rootfsGid {
		return true, nil
	}

	return false, nil
}

// checkUidShifting returns the type of UID shifting needed (if any) for the
// container. The first return value indicates the type of UID shifting to be
// used for the container's rootfs, while the second indicates the type of UID
// shifting for container bind-mounts.
func CheckUidShifting(sysMgr *Mgr, spec *specs.Spec) (sh.IDShiftType, sh.IDShiftType, error) {

	shiftfsOk := sysMgr.Config.ShiftfsOk
	shiftfsOnOvfsOk := sysMgr.Config.ShiftfsOnOverlayfsOk

	idMapMountOk := sysMgr.Config.IDMapMountOk
	ovfsOnIDMapMountOk := sysMgr.Config.OverlayfsOnIDMapMountOk

	rootfsShiftType := sysMgr.Config.RootfsUidShiftType

	if rootfsShiftType == sh.NoShift {

		useShiftfsOnRootfs := false
		useIDMapMountOnRootfs := false

		rootPathFs, err := libutils.GetFsName(spec.Root.Path)
		if err != nil {
			return sh.NoShift, sh.NoShift, err
		}

		if idMapMountOk {
			if rootPathFs == "overlayfs" && ovfsOnIDMapMountOk {
				useIDMapMountOnRootfs = true
			}
		}

		if shiftfsOk {
			if rootPathFs == "overlayfs" && shiftfsOnOvfsOk {
				useShiftfsOnRootfs = true
			}
		}

		needShiftOnRootfs, err := needUidShiftOnRootfs(spec)
		if err != nil {
			return sh.NoShift, sh.NoShift, fmt.Errorf("failed to check uid-shifting requirement on rootfs: %s", err)
		}

		// Check uid shifting type to be used for the container's rootfs.
		//
		// We do it via ID-mapping (preferably) or via shiftfs (if available on
		// the host) or by chown'ing the rootfs hierarchy. Chowning is the least
		// preferred and slowest approach, but won't disrupt anything on the host
		// since the container's rootfs is dedicated to the container (no other
		// entity in the system will use it while the container is running).
		if needShiftOnRootfs {
			if useIDMapMountOnRootfs {
				rootfsShiftType = sh.IDMappedMount
			} else if useShiftfsOnRootfs {
				rootfsShiftType = sh.Shiftfs
			} else {
				rootfsShiftType = sh.Chown
			}
		}
	}

	// Check uid shifting type to be used for the container's bind mounts.
	//
	// For bind mounts, we use ID-mapping or shiftfs, but never chown. Chowning
	// for bind mounts is not a good idea since we don't know what's being bind
	// mounted (e.g., the bind mount could be a user's home dir, a critical
	// system file, etc.).
	bindMountShiftType := sh.NoShift

	if idMapMountOk && shiftfsOk {
		bindMountShiftType = sh.IDMappedMountOrShiftfs
	} else if idMapMountOk {
		bindMountShiftType = sh.IDMappedMount
	} else if shiftfsOk {
		bindMountShiftType = sh.Shiftfs
	}

	return rootfsShiftType, bindMountShiftType, nil
}

// CheckHostConfig checks if the host is configured appropriately to run a
// container with sysbox
func CheckHostConfig(context *cli.Context, spec *specs.Spec) error {

	distro, err := linuxUtils.GetDistro()
	if err != nil {
		return err
	}

	if !context.GlobalBool("no-kernel-check") {
		if err := checkKernelVersion(distro); err != nil {
			return fmt.Errorf("kernel version check failed: %v", err)
		}
	}

	if err := checkUnprivilegedUserns(); err != nil {
		return err
	}

	return nil
}
