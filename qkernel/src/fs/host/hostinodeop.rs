// Copyright (c) 2021 Quark Container Authors
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

use alloc::sync::Arc;
use alloc::sync::Weak;
use spin::Mutex;
use alloc::string::ToString;
use alloc::string::String;
use core::any::Any;
use core::ops::Deref;
use alloc::vec::Vec;
use alloc::boxed::Box;

use socket::unix::transport::unix::BoundEndpoint;
use super::super::super::guestfdnotifier::*;
use super::super::super::qlib::common::*;
use super::super::super::qlib::range::*;
use super::super::super::memmgr::mapping_set::*;
use super::super::super::qlib::mem::areaset::*;
use super::super::super::kernel::time::*;
use super::super::super::qlib::linux::time::*;
use super::super::super::qlib::linux_def::*;
use super::super::super::task::*;
use super::super::super::qlib::auth::*;
use super::super::super::memmgr::mm::*;
use super::super::super::qlib::addr::*;
use super::super::super::kernel::waiter::queue::*;
use super::super::super::Kernel::HostSpace;
use super::super::super::IOURING;

use super::super::attr::*;
use super::*;
use super::util::*;
use super::hostfileop::*;
use super::super::file::*;
use super::super::inode::*;
use super::super::dirent::*;
use super::super::flags::*;

pub struct Mappable {
    //need acquire when read/write f2p and p2m mapps as they
    //pub lock: QLock,
    pub lock: Arc<Mutex<()>>,

    //addr mapping from file offset to physical address
    pub f2pmap: BTreeMap<u64, u64>,

    // mappings tracks mappings of the cached file object into
    // memmap.MappingSpaces.
    pub mapping: AreaSet<MappingsOfRange>,

    pub chunkrefs: BTreeMap<u64, i32>,
}

impl Mappable {
    pub fn IncrRefOn(&mut self, fr: &Range) {
        let mut chunkStart = fr.Start() & !CHUNK_MASK;
        while chunkStart < fr.End() {
            let mut refs = match self.chunkrefs.get(&chunkStart) {
                None => 0,
                Some(v) => *v
            };

            refs += PagesInChunk(fr, chunkStart);
            self.chunkrefs.insert(chunkStart, refs);

            chunkStart += CHUNK_SIZE;
        }
    }

    pub fn DecrRefOn(&mut self, fr: &Range) {
        let mut chunkStart = fr.Start() & !CHUNK_MASK;
        while chunkStart < fr.End() {
            let mut refs = match self.chunkrefs.get(&chunkStart) {
                None => 0,
                Some(v) => *v
            };

            refs -= PagesInChunk(fr, chunkStart);

            if refs == 0 {
                let phyAddr = match self.f2pmap.get(&chunkStart) {
                    None => {
                        info!("HostMappable::RemovePhysicalMapping fileOffset {:x} doesn't exist", chunkStart);
                        //for kernel pma registation, tehre is no phymapping,
                        return;
                    }
                    Some(offset) => *offset,
                };

                HostSpace::MUnmap(phyAddr, CHUNK_SIZE);

                self.f2pmap.remove(&chunkStart);

            } else if refs > 0 {
                self.chunkrefs.insert(chunkStart, refs);
            } else {
                panic!("Mappable::DecrRefOn get negative refs {}, pages is {}, fr is {:x?}",
                       refs, PagesInChunk(fr, chunkStart), fr)
            }

            chunkStart += CHUNK_SIZE;
        }
    }
}

pub fn PagesInChunk(r: &Range, chunkStart: u64) -> i32 {
    assert!(chunkStart & CHUNK_MASK == 0, "chunkStart is {:x}", chunkStart);
    let chunkRange = Range::New(chunkStart, CHUNK_SIZE);
    return (r.Intersect(&chunkRange).Len() / MemoryDef::PAGE_SIZE) as i32;
}

impl Default for Mappable {
    fn default() -> Self {
        return Self {
            lock: Arc::new(Mutex::new(())),
            //lock: QLock::default(),
            f2pmap: BTreeMap::new(),
            mapping: AreaSet::New(0, core::u64::MAX),
            chunkrefs: BTreeMap::new(),
        }
    }
}

pub struct HostInodeOpIntern {
    pub mops: Arc<Mutex<MountSourceOperations>>,
    //this should be SuperOperations
    pub HostFd: i32,
    pub WouldBlock: bool,
    pub Writeable: bool,
    pub sattr: StableAttr,
    pub queue: Queue,
    pub errorcode: i64,

    pub mappable: Option<Box<Mappable>>,
}

impl Default for HostInodeOpIntern {
    fn default() -> Self {
        return Self {
            mops: Arc::new(Mutex::new(SimpleMountSourceOperations::default())),
            HostFd: -1,
            WouldBlock: false,
            Writeable: false,
            sattr: StableAttr::default(),
            queue: Queue::default(),
            errorcode: 0,
            mappable: None,
        }
    }
}

impl Drop for HostInodeOpIntern {
    fn drop(&mut self) {
        if self.HostFd == -1 {
            //default fd
            return
        }

        RemoveFD(self.HostFd);
        AsyncClose(self.HostFd);
    }
}

impl HostInodeOpIntern {
    pub fn New(mops: &Arc<Mutex<MountSourceOperations>>, fd: i32, wouldBlock: bool, fstat: &LibcStat, writeable: bool) -> Self {
        let mut ret = Self {
            mops: mops.clone(),
            HostFd: fd,
            WouldBlock: wouldBlock,
            Writeable: writeable,
            sattr: fstat.StableAttr(),
            queue: Queue::default(),
            errorcode: 0,
            mappable: None,
        };

        if ret.CanMap() {
            ret.mappable = Some(Box::new(Mappable::default()));
        }

        return ret;
    }

    /*********************************start of mappable****************************************************************/
    fn Mappable(&mut self) -> &mut Mappable {
        return self.mappable.as_deref_mut().unwrap();
    }

    //add mapping between physical address and file offset, offset must be hugepage aligned
    pub fn AddPhyMapping(&mut self, phyAddr: u64, offset: u64) {
        assert!(offset & CHUNK_MASK == 0, "HostMappable::AddPhysicalMap offset should be hugepage aligned");

        let h = self;
        h.Mappable().f2pmap.insert(offset, phyAddr);
    }

    pub fn IncrRefOn(&mut self, fr: &Range) {
        return self.Mappable().IncrRefOn(fr);
    }

    pub fn DecrRefOn(&mut self, fr: &Range, ) {
        return self.Mappable().DecrRefOn(fr);
    }

    /*********************************end of mappable****************************************************************/

    pub fn SetMaskedAttributes(&self, mask: &AttrMask, attr: &UnstableAttr) -> Result<()> {
        if mask.Empty() {
            return Ok(())
        }

        if mask.UID || mask.GID {
            return Err(Error::SysError(SysErr::EPERM))
        }

        if mask.Perms {
            let ret = Fchmod(self.HostFd, attr.Perms.LinuxMode()) as i32;
            if ret < 0 {
                return Err(Error::SysError(-ret))
            }
        }

        if mask.Size {
            let ret = Ftruncate(self.HostFd, attr.Size) as i32;
            if ret < 0 {
                return Err(Error::SysError(-ret))
            }
        }

        if mask.AccessTime || mask.ModificationTime {
            let ts = InterTimeSpec {
                ATime: attr.AccessTime,
                ATimeOmit: !mask.AccessTime,
                MTime: attr.ModificationTime,
                MTimeOmit: !mask.ModificationTime,
                ..Default::default()
            };

            return SetTimestamps(self.HostFd, &ts);
        }

        return Ok(())
    }

    pub fn Sync(&self) -> Result<()> {
        let ret = Fsync(self.HostFd);
        if ret < 0 {
            return Err(Error::SysError(-ret))
        }

        return Ok(())
    }

    pub fn HostFd(&self) -> i32 {
        return self.HostFd
    }

    pub fn Allocate(&self, offset: i64, len: i64) -> Result<()> {
        let ret = Fallocate(self.HostFd, 0, offset, len) as i32;
        if ret < 0 {
            return Err(Error::SysError(-ret))
        }

        Ok(())
    }

    pub fn WouldBlock(&self) -> bool {
        return self.WouldBlock
    }

    pub fn StableAttr(&self) -> StableAttr {
        return self.sattr;
    }

    pub fn CanMap(&self) -> bool {
        return self.sattr.Type == InodeType::RegularFile ||
            self.sattr.Type == InodeType::SpecialFile;
    }

    pub fn InodeType(&self) -> InodeType {
        return self.sattr.Type;
    }
}

#[derive(Clone)]
pub struct HostInodeOpWeak(pub Weak<Mutex<HostInodeOpIntern>>);

impl HostInodeOpWeak {
    pub fn Upgrade(&self) -> Option<HostInodeOp> {
        let f = match self.0.upgrade() {
            None => return None,
            Some(f) => f,
        };

        return Some(HostInodeOp(f));
    }
}

#[derive(Clone)]
pub struct HostInodeOp(pub Arc<Mutex<HostInodeOpIntern>>);

impl PartialEq for HostInodeOp {
    fn eq(&self, other: &Self) -> bool {
        return Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for HostInodeOp {}

impl Default for HostInodeOp {
    fn default() -> Self {
        return Self(Arc::new(Mutex::new(HostInodeOpIntern::default())))
    }
}

impl Deref for HostInodeOp {
    type Target = Arc<Mutex<HostInodeOpIntern>>;

    fn deref(&self) -> &Arc<Mutex<HostInodeOpIntern>> {
        &self.0
    }
}

impl HostInodeOp {
    pub fn New(mops: &Arc<Mutex<MountSourceOperations>>, fd: i32, wouldBlock: bool, fstat: &LibcStat, writeable: bool) -> Self {
        let intern = Arc::new(Mutex::new(HostInodeOpIntern::New(mops, fd, wouldBlock, fstat, writeable)));

        let ret = Self(intern);
        AddFD(fd, &ret);
        return ret
    }

    pub fn Downgrade(&self) -> HostInodeOpWeak {
        return HostInodeOpWeak(Arc::downgrade(&self.0))
    }

    pub fn HostFd(&self) -> i32 {
        return self.lock().HostFd
    }

    pub fn StableAttr(&self) -> StableAttr {
        return self.lock().sattr;
    }

    pub fn Queue(&self) -> Queue {
        return self.lock().queue.clone();
    }

    pub fn GetHostFileOp(&self, _task: &Task) -> Arc<HostFileOp> {
        let hostFileOp = HostFileOp {
            InodeOp: self.clone(),
            DirCursor: Mutex::new("".to_string()),
            //Buf: HostFileBuf::None,
        };
        return Arc::new(hostFileOp)
    }

    // return (st_size, st_blocks)
    pub fn Size(&self) -> Result<(i64, i64)> {
        let mut s: LibcStat = Default::default();
        let hostfd = self.lock().HostFd;
        let ret = Fstat(hostfd, &mut s) as i32;
        if ret < 0 {
            return Err(Error::SysError(-ret as i32))
        }

        return Ok((s.st_size, s.st_blocks))
    }

    /*********************************start of mappable****************************************************************/

    //add mapping between file offset and the <MappingSpace(i.e. memorymanager), Virtual Address>
    pub fn AddMapping(&self, ms: &MemoryManager, ar: &Range, offset: u64, writeable: bool) -> Result<()> {
        let mut h = self.lock();

        h.Mappable().mapping.AddMapping(ms, ar, offset, writeable);
        h.Mappable().IncrRefOn(&Range::New(offset, ar.Len()));
        return Ok(())
    }

    pub fn RemoveMapping(&self, ms: &MemoryManager, ar: &Range, offset: u64, writeable: bool) -> Result<()> {
        let mut h = self.lock();

        h.Mappable().mapping.RemoveMapping(ms, ar, offset, writeable);
        h.Mappable().DecrRefOn(&Range::New(offset, ar.Len()));
        return Ok(())
    }

    pub fn CopyMapping(&self, ms: &MemoryManager, _srcAr: &Range, dstAR: &Range, offset: u64, writeable: bool) -> Result<()> {
        return self.AddMapping(ms, dstAR, offset, writeable);
    }

    pub fn FD(&self) -> i32 {
        let ret = self.lock().HostFd;
        return ret
    }

    //get phyaddress ranges for the file range
    pub fn MapInternal(&self, task: &Task, fr: &Range) -> Result<Vec<IoVec>> {
        let mut chunkStart = fr.Start() & !HUGE_PAGE_MASK;

        self.Fill(task, chunkStart, fr.End())?;
        let mut res = Vec::new();

        let mut h = self.lock();
        while chunkStart < fr.End() {
            let phyAddr = h.Mappable().f2pmap.get(&chunkStart).unwrap();
            let mut startOffset = 0;
            if chunkStart < fr.Start() {
                startOffset = fr.Start() - chunkStart;
            }

            let mut endOff = CHUNK_SIZE;
            if chunkStart + CHUNK_SIZE > fr.End() {
                endOff = fr.End() - chunkStart;
            }

            res.push(IoVec::NewFromAddr(phyAddr + startOffset, (endOff - startOffset) as usize));
            chunkStart += CHUNK_SIZE;
        }

        return Ok(res);
    }

    // map one page from file offsetFile to phyAddr
    pub fn MapFilePage(&self, task: &Task, fileOffset: u64) -> Result<u64> {
        let chunkStart = fileOffset & !HUGE_PAGE_MASK;
        self.Fill(task, chunkStart, fileOffset + PAGE_SIZE)?;
        let mut h = self.lock();
        let phyAddr = h.Mappable().f2pmap.get(&chunkStart).unwrap();
        return Ok(phyAddr + (fileOffset - chunkStart))
    }

    pub fn GetPhyRanges(&self, fr: &Range) -> Vec<Range> {
        let mut chunkStart = fr.Start() & !HUGE_PAGE_MASK;
        let mut rs = Vec::new();

        let mut h = self.lock();
        while chunkStart < fr.End() {
            match h.Mappable().f2pmap.get(&chunkStart) {
                None => (),
                Some(phyAddr) => {
                    rs.push(Range::New(*phyAddr, HUGE_PAGE_SIZE));
                }
            }

            chunkStart += CHUNK_SIZE;
        }

        return rs;
    }

    pub fn MMapChunk(&self, offset: u64) -> Result<u64> {
        let writeable = self.lock().Writeable;

        let prot = if writeable {
            (MmapProt::PROT_WRITE | MmapProt::PROT_READ) as i32
        } else {
            MmapProt::PROT_READ as i32
        };

        let phyAddr = self.MapFileChunk(offset, prot)?;
        self.lock().AddPhyMapping(phyAddr, offset);
        return Ok(phyAddr)
    }

    pub fn MapFileChunk(&self, offset: u64, prot: i32) -> Result<u64> {
        assert!(offset & CHUNK_MASK == 0, "MapFile offset must be chunk aligned");

        let fd = self.lock().HostFd();
        let ret = HostSpace::MMapFile(CHUNK_SIZE, fd, offset, prot);

        if ret < 0 {
            return Err(Error::SysError(-ret as i32))
        }

        let phyAddr = ret as u64;
        return Ok(phyAddr)
    }

    //fill the holes for the file range by mmap
    //start must be Hugepage aligned
    fn Fill(&self, _task: &Task, start: u64, end: u64) -> Result<()> {
        let lock = self.lock().Mappable().lock.clone();
        let _l = lock.lock();
        //task.blocker.Qlock(task, &lock)?;

        let mut start = start;

        let mut holes = Vec::new();

        while start < end {
            match self.lock().Mappable().f2pmap.get(&start) {
                None => holes.push(start),
                Some(_) => (),
            }

            start += HUGE_PAGE_SIZE;
        }

        for offset in holes {
            self.MMapChunk(offset)?;
        }
        return Ok(())
    }

    /*********************************end of mappable****************************************************************/
}

impl InodeOperations for HostInodeOp {
    fn as_any(&self) -> &Any {
        self
    }

    fn IopsType(&self) -> IopsType {
        return IopsType::HostInodeOp;
    }

    fn InodeType(&self) -> InodeType {
        return self.lock().sattr.Type;
    }

    fn InodeFileType(&self) -> InodeFileType{
        return InodeFileType::Host;
    }

    fn WouldBlock(&self) -> bool {
        return self.lock().WouldBlock
    }

    fn Lookup(&self, _task: &Task, dir: &Inode, name: &str) -> Result<Dirent> {
        let (fd, writeable, fstat) = TryOpenAt(self.HostFd(), name)?;

        let ms = dir.lock().MountSource.clone();
        let inode = Inode::NewHostInode(&ms, fd, &fstat, writeable)?;

        let ret = Ok(Dirent::New(&inode, name));
        return ret;
    }

    fn Create(&self, task: &Task, dir: &mut Inode, name: &str, flags: &FileFlags, perm: &FilePermissions) -> Result<File> {
        //let fd = openAt(self.HostFd(), name, (LibcConst::O_RDWR | LibcConst::O_CREAT | LibcConst::O_EXCL) as i32, perm.LinuxMode());

        let owner = task.FileOwner();

        let mut newFlags = *flags;

        // the fd might be use for other read/write operations todo: handle this more elegant
        newFlags.Read = true;
        newFlags.Write = true;

        let (fd, fstat) = createAt(self.HostFd(), name, newFlags.ToLinux() | LibcConst::O_CREAT as i32, perm.LinuxMode(), owner.UID.0, owner.GID.0)?;

        let mountSource = dir.lock().MountSource.clone();

        let inode = Inode::NewHostInode(&mountSource, fd, &fstat, true)?;
        let dirent = Dirent::New(&inode, name);

        let file = inode.GetFile(task, &dirent, flags)?;
        return Ok(file)
    }

    fn CreateDirectory(&self, task: &Task, _dir: &mut Inode, name: &str, perm: &FilePermissions) -> Result<()> {
        let owner = task.FileOwner();

        let ret = Mkdirat(self.HostFd(), name, perm.LinuxMode(), owner.UID.0, owner.GID.0);
        if ret < 0 {
            return Err(Error::SysError(-ret as i32))
        }

        return Ok(())
    }

    fn CreateLink(&self, _task: &Task, _dir: &mut Inode, oldname: &str, newname: &str) -> Result<()> {
        let ret = SymLinkAt(oldname, self.HostFd(), newname);

        if ret < 0 {
            return Err(Error::SysError(-ret as i32))
        }

        return Ok(())
    }

    fn CreateHardLink(&self, _task: &Task, _dir: &mut Inode, _target: &Inode, _name: &str) -> Result<()> {
        return Err(Error::SysError(SysErr::EPERM))
    }

    fn CreateFifo(&self, _task: &Task, _dir: &mut Inode, _name: &str, _perm: &FilePermissions) -> Result<()> {
        return Err(Error::SysError(SysErr::EPERM))
    }

    fn Remove(&self, _task: &Task, _dir: &mut Inode, name: &str) -> Result<()> {
        let flags = 0; //ATType::AT_REMOVEDIR

        let ret = UnLinkAt(self.HostFd(), name, flags);

        if ret < 0 {
            return Err(Error::SysError(-ret as i32))
        }

        return Ok(())
    }

    fn RemoveDirectory(&self, _task: &Task, _dir: &mut Inode, name: &str) -> Result<()> {
        let flags = ATType::AT_REMOVEDIR;

        let ret = UnLinkAt(self.HostFd(), name, flags);

        if ret < 0 {
            return Err(Error::SysError(-ret as i32))
        }

        return Ok(())
    }

    fn Rename(&self, _task: &Task, _dir: &mut Inode, oldParent: &Inode, oldname: &str, newParent: &Inode, newname: &str, _replacement: bool) -> Result<()> {
        let oldParent = match oldParent.lock().InodeOp.as_any().downcast_ref::<HostInodeOp>() {
            Some(p) => p.HostFd(),
            None => panic!("&InodeOp isn't a HostInodeOp!"),
        };

        let newParent = match newParent.lock().InodeOp.as_any().downcast_ref::<HostInodeOp>() {
            Some(p) => p.HostFd(),
            None => panic!("&InodeOp isn't a HostInodeOp!"),
        };

        let ret = RenameAt(oldParent, oldname, newParent, newname);

        if ret < 0 {
            return Err(Error::SysError(-ret as i32))
        }

        return Ok(())
    }

    fn Bind(&self, _task: &Task, _dir: &Inode, _name: &str, _data: &BoundEndpoint, _perms: &FilePermissions) -> Result<Dirent> {
        return Err(Error::SysError(SysErr::ENOTDIR))
    }

    fn BoundEndpoint(&self, _task: &Task, _inode: &Inode, _path: &str) -> Option<BoundEndpoint> {
        return None
    }

    fn GetFile(&self, task: &Task, _dir: &Inode, dirent: &Dirent, flags: FileFlags) -> Result<File> {
        let fops = self.GetHostFileOp(task);

        let inode = dirent.Inode();
        let wouldBlock = inode.lock().InodeOp.WouldBlock();

        return Ok(File::NewHostFile(dirent, &flags, fops, wouldBlock))
    }

    fn UnstableAttr(&self, task: &Task, _dir: &Inode) -> Result<UnstableAttr> {
        let useStatx = false;

        if !useStatx {
            let mut s: LibcStat = Default::default();
            let hostfd = self.lock().HostFd;
            let ret = Fstat(hostfd, &mut s) as i32;
            if ret < 0 {
                return Err(Error::SysError(-ret as i32))
            }

            let mops = self.lock().mops.clone();
            return Ok(s.UnstableAttr(&mops))
        } else {
            let mut s: Statx = Default::default();
            let hostfd = self.lock().HostFd;
            print!("UnstableAttr  .... fd is {}", hostfd);
            let addr : i8 = 0;
            let ret = IOURING.Statx(task,
                                    hostfd,
                                    &addr as *const _ as u64,
                                    &mut s as * mut _ as u64,
                                    ATType::AT_EMPTY_PATH,
                                    StatxMask::STATX_BASIC_STATS);
            print!("UnstableAttr fd is {} ret is {}....", hostfd, ret);
            if ret < 0 {
                return Err(Error::SysError(-ret as i32))
            }

            let mops = self.lock().mops.clone();
            return Ok(s.UnstableAttr(&mops))
        }
    }

    //fn StableAttr(&self) -> &StableAttr;
    fn Getxattr(&self, _dir: &Inode, _name: &str) -> Result<String> {
        return Err(Error::SysError(SysErr::EOPNOTSUPP))
    }

    fn Setxattr(&self, _dir: &mut Inode, _name: &str, _value: &str) -> Result<()> {
        return Err(Error::SysError(SysErr::EOPNOTSUPP))
    }

    fn Listxattr(&self, _dir: &Inode) -> Result<Vec<String>> {
        return Err(Error::SysError(SysErr::EOPNOTSUPP))
    }

    fn Check(&self, task: &Task, inode: &Inode, reqPerms: &PermMask) -> Result<bool> {
        return ContextCanAccessFile(task, inode, reqPerms)
    }

    fn SetPermissions(&self, _task: &Task, _dir: &mut Inode, f: FilePermissions) -> bool {
        return Fchmod(self.HostFd(), f.LinuxMode()) == 0
    }

    fn SetOwner(&self, _task: &Task, _dir: &mut Inode, owner: &FileOwner) -> Result<()> {
        let ret = FChown(self.HostFd(), owner.UID.0, owner.GID.0);

        if ret < 0 {
            return Err(Error::SysError(-ret as i32))
        };

        return Ok(())
    }

    fn SetTimestamps(&self, _task: &Task, _dir: &mut Inode, ts: &InterTimeSpec) -> Result<()> {
        if ts.ATimeOmit && ts.MTimeOmit {
            return Ok(())
        }

        let mut sts: [Timespec; 2] = [Timespec::default(); 2];

        sts[0] = TimespecFromTimestamp(ts.ATime, ts.ATimeOmit, ts.ATimeSetSystemTime);
        sts[1] = TimespecFromTimestamp(ts.MTime, ts.MTimeOmit, ts.MTimeSetSystemTime);

        let ret = HostSpace::Futimens(self.HostFd(), &sts as * const _ as u64);
        if ret < 0 {
            return Err(Error::SysError(-ret as i32))
        }

        return Ok(())
    }

    fn Truncate(&self, _task: &Task, _dir: &mut Inode, size: i64) -> Result<()> {
        let ret = Ftruncate(self.HostFd(), size);

        if ret < 0 {
            return Err(Error::SysError(-ret as i32))
        }

        return Ok(())
    }

    fn Allocate(&self, _task: &Task, _dir: &mut Inode, offset: i64, length: i64) -> Result<()> {
        let ret = Fallocate(self.HostFd(), 0, offset, length);

        if ret < 0 {
            return Err(Error::SysError(-ret as i32))
        }

        return Ok(())
    }

    fn ReadLink(&self, _task: &Task,_dir: &Inode) -> Result<String> {
        return ReadLinkAt(self.HostFd(), &"".to_string())
    }

    fn GetLink(&self, _task: &Task, dir: &Inode) -> Result<Dirent> {
        if !dir.StableAttr().IsSymlink() {
            return Err(Error::SysError(SysErr::ENOLINK))
        }

        return Err(Error::ErrResolveViaReadlink)
    }

    fn AddLink(&self, _task: &Task) {
        //return Err(Error::None)
    }

    fn DropLink(&self, _task: &Task) {
        //return Err(Error::None)
    }

    fn IsVirtual(&self) -> bool {
        false
    }

    fn Sync(&self) -> Result<()> {
        return self.lock().Sync();
    }

    fn StatFS(&self, _task: &Task) -> Result<FsInfo> {
        let mut statfs = LibcStatfs::default();

        let fd = self.HostFd();
        let ret = HostSpace::Fstatfs(fd, &mut statfs as * mut _ as u64);
        if ret < 0 {
            return Err(Error::SysError(-ret as i32))
        }

        let mut fsInfo = FsInfo::default();
        fsInfo.Type = statfs.Type;
        fsInfo.TotalBlocks = statfs.Blocks;
        fsInfo.FreeBlocks = statfs.BlocksFree;
        fsInfo.TotalFiles = statfs.Files;
        fsInfo.FreeFiles = statfs.FilesFree;

        return Ok(fsInfo)
    }

    fn Mappable(&self) -> Result<HostInodeOp> {
        let inodeType = self.lock().InodeType();
        if inodeType == InodeType::RegularFile {
            return Ok(self.clone())
        } else {
            return Err(Error::SysError(SysErr::ENODEV))
        }
    }
}

#[cfg(test1)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use alloc::sync::Arc;
    use spin::Mutex;
    use std::fs::*;

    use super::super::util::*;
    use super::super::super::mount::*;
    use super::super::super::attr::*;
    use super::super::super::inode::*;
    use super::super::super::dentry::*;
    use super::super::super::path::*;
    use super::super::super::file;
    use super::super::super::dirent::*;
    use super::super::super::flags::*;
    use super::super::super::filesystems::*;

    #[test]
    fn TestMultipleReadDir() {
        let root = "/tmp/root";
        remove_dir_all(root).ok();
        create_dir(root).unwrap();

        let rootStr = root.to_string();

        File::create(Join(&rootStr, &"a.txt".to_string())).unwrap();
        File::create(Join(&rootStr, &"b.txt".to_string())).unwrap();

        let (fd, _) = TryOpenAt(-100, &rootStr);

        let ms = Arc::new(Mutex::new(MountSource::NewHostMountSource(&rootStr, &ROOT_OWNER, &WhitelistFileSystem::New(), &MountSourceFlags::default(), false)));
        let n = Inode::NewHostInode(&ms, fd).unwrap();
        let dirent = Dirent::New(&n, &"readdir".to_string());
        let openFile = n.GetFile(&dirent, &FileFlags { Read: true, ..Default::default() }).unwrap();

        let mut serializer1 = CollectEntriesSerilizer::New();
        let mut c1 = DirCtx::New(&mut serializer1);

        let mut serializer2 = CollectEntriesSerilizer::New();
        let mut c2 = DirCtx::New(&mut serializer2);

        let (_, _) = openFile.lock().FileOp.borrow_mut().IterateDir(&dirent, &mut c1, 0);
        let (_, _) = openFile.lock().FileOp.borrow_mut().IterateDir(&dirent, &mut c2, 0);

        assert!(serializer1.Entries.contains_key(&"a.txt".to_string()));
        assert!(serializer1.Entries.contains_key(&"b.txt".to_string()));
        assert!(serializer2.Entries.contains_key(&"a.txt".to_string()));
        assert!(serializer2.Entries.contains_key(&"b.txt".to_string()));
    }

    #[test]
    fn TestCloseFD() {
        let mut p: [i32; 2] = [0, 0];

        let _res = Pipe(&mut p);

        file::File::NewFileFromFd(p[1], &ROOT_OWNER, false).unwrap();
        let mut buf: [u8; 10] = [0; 10];
        let res = Read(p[0], &mut buf[0] as *const u8 as u64, buf.len() as u64);
        assert!(res == 0);
    }
}