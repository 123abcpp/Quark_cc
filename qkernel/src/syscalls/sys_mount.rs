// Copyright (c) 2021 Quark Container Authors / 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use alloc::string::ToString;

use crate::qlib::kernel::fs::filesystems::FindFilesystem;

use super::super::fs::dirent::*;
use super::super::qlib::common::*;
use super::super::qlib::linux_def::*;
use super::super::qlib::kernel::fs::filesystems::MountSourceFlags;
use super::super::syscalls::syscalls::*;
use super::super::task::*;
use super::sys_file::*;

// SysMount implements Linux syscall mount(2).
// Currently All the files are in one mount namespce, no difference between shared/private
pub fn SysMount(task: &mut Task, args: &SyscallArguments) -> Result<i64> {
	let sourceAddr = args.arg0 as u64;
	let targetAddr = args.arg1 as u64;
	let typeAddr = args.arg2 as u64;
	let mut flags = args.arg3 as u64;
	let dataAddr = args.arg4 as u64;

	debug!("sys_mount flags:{:x}", flags);
	// Must have CAP_SYS_ADMIN in the current mount namespace's associated user
	// namespace.
	let creds = task.Creds();
	if !creds.HasCapabilityIn(Capability::CAP_SYS_ADMIN, &task.MountNS().userns) {
		return Err(Error::SysError(SysErr::EPERM));
	}

	// Ignore magic value that was required before Linux 2.4.
	if flags & LibcConst::MS_MGC_MSK == LibcConst::MS_MGC_VAL {
		flags = flags & !LibcConst::MS_MGC_MSK
	}

	// Silently allow MS_NOSUID, since we don't implement set-id bits anyway.
	let unsupported = LibcConst::MS_UNBINDABLE | LibcConst::MS_MOVE | LibcConst::MS_NODIRATIME | LibcConst::MS_NODEV | LibcConst::MS_NOSUID;

	// Linux just allows passing any flags to mount(2) - it won't fail when
	// unknown or unsupported flags are passed. Since we don't implement
	// everything, we fail explicitly on flags that are unimplemented.
	if flags&(unsupported) != 0 {
		return Err(Error::SysError(SysErr::EINVAL));
	}

	let (targetPath, _) = copyInPath(task, targetAddr, false)?;

	let mut opts = MountSourceFlags::default();
	if flags&(LibcConst::MS_NOATIME|LibcConst::MS_STRICTATIME) == LibcConst::MS_NOATIME {
		opts.NoAtime = true
	}
	if flags&LibcConst::MS_NOEXEC == LibcConst::MS_NOEXEC {
		opts.NoExec = true
	}
	if flags&LibcConst::MS_RDONLY == LibcConst::MS_RDONLY {
		opts.ReadOnly = true
	}
	let mut data = "".to_string();
	if dataAddr != 0 {
		(data, _) = copyInPath(task, dataAddr, true)?;
	}

	if flags&LibcConst::MS_REMOUNT != 0 {
		debug!("Remount not supported yet");
		return Err(Error::SysError(SysErr::EINVAL));
	}

	let (sourcePath, _) = copyInPath(task, sourceAddr, false)?;

	if flags&LibcConst::MS_BIND != 0 {
		debug!("Get sys_mount Bind!");
		fileOpOn(
			task,
			ATType::AT_FDCWD,
			&sourcePath,
			true,
			&mut |_root: &Dirent, d: &Dirent, _remainingTraversals: u32| -> Result<()> {
				let source_inode = &d.inode;
				debug!("Get source inode {}", source_inode.ID());
				fileOpOn(
					task,
					ATType::AT_FDCWD,
					&targetPath,
					true,
					&mut |_root: &Dirent, d: &Dirent, _remainingTraversals: u32| -> Result<()> {
						task.MountNS().Mount(d, source_inode)
					},
				)
			},
		)?;

		return Ok(0);
	}


	let (type_name, _) = copyInPath(task, typeAddr, false)?;
	let filesystem;
	match FindFilesystem(&type_name) {
		Some(system) => filesystem = system,
		None => return Err(Error::SysError(SysErr::ENODEV)),
	}
	
	let inode = filesystem
        .lock()
        .Mount(task, &"none".to_string(), &opts, &data)?;

	
	fileOpOn(
        task,
        ATType::AT_FDCWD,
        &targetPath,
        true,
        &mut |_root: &Dirent, d: &Dirent, _remainingTraversals: u32| -> Result<()> {
			task.MountNS().Mount(d, &inode)
        },
    )?;
	return Ok(0);
}

// Umount2 implements Linux syscall umount2(2).
pub fn SysUmount2(task: &mut Task, args: &SyscallArguments) -> Result<i64>{
	let addr = args.arg0 as u64;
	let flags = args.arg1 as u64;

	// Must have CAP_SYS_ADMIN in the mount namespace's associated user
	// namespace.
	//
	// Currently, this is always the init task's user namespace.
	let creds = task.Creds();
	if !creds.HasCapabilityIn(Capability::CAP_SYS_ADMIN, &task.MountNS().userns) {
		return Err(Error::SysError(SysErr::EPERM));
	}

	let unsupported = LibcConst::MNT_FORCE | LibcConst::MNT_EXPIRE;
	if flags&(unsupported) != 0 {
		return Err(Error::SysError(SysErr::EINVAL));
	}

	let (path, _) = copyInPath(task, addr, false)?;
	
	let resolve = flags & LibcConst::UMOUNT_NOFOLLOW > 0;

	fileOpOn(
        task,
        ATType::AT_FDCWD,
        &path,
        resolve,
        &mut |_root: &Dirent, d: &Dirent, _remainingTraversals: u32| -> Result<()> {
			task.MountNS().Unmount(d, flags & LibcConst::MNT_DETACH > 0)
        },
    )?;
	return Ok(0);
}
