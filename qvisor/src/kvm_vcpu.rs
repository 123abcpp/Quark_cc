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

use alloc::alloc::{Layout, alloc};
use alloc::slice;
use core::sync::atomic::Ordering;
use kvm_bindings::kvm_sregs;
use kvm_bindings::kvm_regs;
use kvm_ioctls::VcpuExit;
use core::mem::size_of;
use libc::*;

use super::*;
use super::syncmgr::*;
//use super::kvm_ctl::*;
use super::qlib::GetTimeCall;
use super::qlib::linux::time::Timespec;
use super::qlib::common::*;
use super::qlib::task_mgr::*;
use super::qlib::linux_def::*;
use super::qlib::pagetable::*;
use super::qlib::perf_tunning::*;
use super::qlib::*;
use super::qlib::vcpu_mgr::*;
use super::qlib::buddyallocator::ZeroPage;
use super::amd64_def::*;
use super::URING_MGR;
use super::QUARK_CONFIG;
use super::runc::runtime::vm::*;

pub fn AlignedAllocate(size: usize, align: usize, zeroData: bool) -> Result<u64> {
    assert!(size % 8 == 0, "AlignedAllocate get unaligned size {:x}", size);
    let layout = Layout::from_size_align(size, align);
    match layout {
        Err(_e) => Err(Error::UnallignedAddress),
        Ok(l) => unsafe {
            let addr = alloc(l);
            if zeroData {
                let arr = slice::from_raw_parts_mut(addr as *mut u64, size / 8);
                for i in 0..512 {
                    arr[i] = 0
                }
            }

            Ok(addr as u64)
        }
    }
}

pub struct HostPageAllocator {
    pub allocator: AlignedAllocator,
}

impl HostPageAllocator {
    pub fn New() -> Self {
        return Self {
            allocator: AlignedAllocator::New(0x1000, 0x10000)
        }
    }
}

impl Allocator for HostPageAllocator {
    fn AllocPage(&self, _incrRef: bool) -> Result<u64> {
       let ret = self.allocator.Allocate()?;
        ZeroPage(ret);
        return Ok(ret);
    }

    fn FreePage(&self, _addr: u64) -> Result<()> {
        panic!("HostPageAllocator doesn't support FreePage");
    }
}

impl RefMgr for HostPageAllocator {
    fn Ref(&self, _addr: u64) -> Result<u64> {
        //panic!("HostPageAllocator doesn't support Ref");
        return Ok(1)
    }

    fn Deref(&self, _addr: u64) -> Result<u64> {
        panic!("HostPageAllocator doesn't support Deref");
    }

    fn GetRef(&self, _addr: u64) -> Result<u64> {
        panic!("HostPageAllocator doesn't support GetRef");
    }
}

pub struct KVMVcpu {
    pub id: usize,
    pub vcpuCnt: usize,
    //index in the cpu arrary
    pub vcpu: kvm_ioctls::VcpuFd,

    pub topStackAddr: u64,
    pub entry: u64,

    pub gdtAddr: u64,
    pub idtAddr: u64,
    pub tssIntStackStart: u64,
    pub tssAddr: u64,

    pub heapStartAddr: u64,
    pub shareSpaceAddr: u64,

    pub autoStart: bool,
    //the pipe id to notify io_mgr
}

//for pub shareSpace: * mut Mutex<ShareSpace>
unsafe impl Send for KVMVcpu {}

impl KVMVcpu {
    pub fn Init(id: usize,
                vcpuCnt: usize,
                vm_fd: &kvm_ioctls::VmFd,
                entry: u64,
                pageAllocatorBaseAddr: u64,
                shareSpaceAddr: u64,
                autoStart: bool) -> Result<Self> {
        const DEFAULT_STACK_PAGES: u64 = qlib::linux_def::MemoryDef::DEFAULT_STACK_PAGES; //64KB
        //let stackAddr = pageAlloc.Alloc(DEFAULT_STACK_PAGES)?;
        let stackSize = DEFAULT_STACK_PAGES << 12;
        let stackAddr = AlignedAllocate(stackSize as usize, stackSize as usize, false).unwrap();
        let topStackAddr = stackAddr + (DEFAULT_STACK_PAGES << 12);


        let gdtAddr = AlignedAllocate(MemoryDef::PAGE_SIZE as usize, MemoryDef::PAGE_SIZE as usize, true).unwrap();
        let idtAddr = AlignedAllocate(MemoryDef::PAGE_SIZE as usize, MemoryDef::PAGE_SIZE as usize, true).unwrap();

        let tssIntStackStart = AlignedAllocate(MemoryDef::PAGE_SIZE as usize, MemoryDef::PAGE_SIZE as usize, true).unwrap();
        let tssAddr = AlignedAllocate(MemoryDef::PAGE_SIZE as usize, MemoryDef::PAGE_SIZE as usize, true).unwrap();

        info!("the tssIntStackStart is {:x}, tssAddr address is {:x}, idt addr is {:x}, gdt addr is {:x}",
            tssIntStackStart, tssAddr, idtAddr, gdtAddr);

        let vcpu = vm_fd.create_vcpu(id as u64).map_err(|e| Error::IOError(format!("io::error is {:?}", e))).expect("create vcpu fail");

        return Ok(Self {
            id: id,
            vcpuCnt,
            vcpu,
            topStackAddr: topStackAddr,
            entry: entry,
            gdtAddr: gdtAddr,
            idtAddr: idtAddr,
            tssIntStackStart: tssIntStackStart,
            tssAddr: tssAddr,
            heapStartAddr: pageAllocatorBaseAddr,
            shareSpaceAddr: shareSpaceAddr,
            autoStart: autoStart,
        })
    }

    fn SetupGDT(&self, sregs: &mut kvm_sregs) {
        let gdtTbl = unsafe {
            std::slice::from_raw_parts_mut(self.gdtAddr as *mut u64, 4096 / 8)
        };

        let KernelCodeSegment = SegmentDescriptor::default().SetCode64(0, 0, 0);
        let KernelDataSegment = SegmentDescriptor::default().SetData(0, 0xffffffff, 0);
        let _UserCodeSegment32 = SegmentDescriptor::default().SetCode64(0, 0, 3);
        let UserDataSegment = SegmentDescriptor::default().SetData(0, 0xffffffff, 3);
        let UserCodeSegment64 = SegmentDescriptor::default().SetCode64(0, 0, 3);

        sregs.cs = KernelCodeSegment.GenKvmSegment(KCODE);
        sregs.ds = UserDataSegment.GenKvmSegment(UDATA);
        sregs.es = UserDataSegment.GenKvmSegment(UDATA);
        sregs.ss = KernelDataSegment.GenKvmSegment(KDATA);
        sregs.fs = UserDataSegment.GenKvmSegment(UDATA);
        sregs.gs = UserDataSegment.GenKvmSegment(UDATA);

        // error!("cs is {:x?}", sregs.cs);
        // error!("ds is {:x?}", sregs.ds);
        // error!("es is {:x?}", sregs.es);
        // error!("ss is {:x?}", sregs.ss);
        // error!("fs is {:x?}", sregs.fs);
        // error!("gs is {:x?}", sregs.gs);

        gdtTbl[1] = KernelCodeSegment.AsU64();
        gdtTbl[2] = KernelDataSegment.AsU64();
        gdtTbl[3] = UserDataSegment.AsU64();
        gdtTbl[4] = UserCodeSegment64.AsU64();

        let stack_end = x86_64::VirtAddr::from_ptr((self.tssIntStackStart + MemoryDef::INTERRUPT_STACK_PAGES * MemoryDef::PAGE_SIZE) as *const u64);

        let tssSegment = self.tssAddr as *mut x86_64::structures::tss::TaskStateSegment;
        unsafe {
            (*tssSegment).interrupt_stack_table[0] = stack_end;
            (*tssSegment).iomap_base = -1 as i16 as u16;
            info!("[{}] the tssSegment stack is {:x}", self.id, self.tssIntStackStart + MemoryDef::INTERRUPT_STACK_PAGES * MemoryDef::PAGE_SIZE);
            let (tssLow, tssHigh, limit) = Self::TSStoDescriptor(&(*tssSegment));

            gdtTbl[5] = tssLow;
            gdtTbl[6] = tssHigh;

            sregs.tr = SegmentDescriptor::New(tssLow).GenKvmSegment(TSS);
            sregs.tr.base = self.tssAddr;
            sregs.tr.limit = limit as u32;
        }
    }

    fn TSS(tss: &x86_64::structures::tss::TaskStateSegment) -> (u64, u16) {
        let addr = tss as *const _ as u64;
        let size = (size_of::<x86_64::structures::tss::TaskStateSegment>() - 1) as u64;
        return (addr, size as u16)
    }


    fn TSStoDescriptor(tss: &x86_64::structures::tss::TaskStateSegment) -> (u64, u64, u16) {
        let (tssBase, tssLimit) = Self::TSS(tss);
        let low = SegmentDescriptor::default().Set(
            tssBase as u32, tssLimit as u32, 0, SEGMENT_DESCRIPTOR_PRESENT |
            SEGMENT_DESCRIPTOR_ACCESS |
            SEGMENT_DESCRIPTOR_WRITE |
            SEGMENT_DESCRIPTOR_EXECUTE);

        let hi = SegmentDescriptor::default().SetHi((tssBase >> 32) as u32);

        return (low.AsU64(), hi.AsU64(), tssLimit);
    }

    fn setup_long_mode(&self) -> Result<()> {
        let mut vcpu_sregs = self.vcpu.get_sregs().map_err(|e| Error::IOError(format!("io::error is {:?}", e)))?;

        //vcpu_sregs.cr0 = CR0_PE | CR0_MP | CR0_AM | CR0_ET | CR0_NE | CR0_WP | CR0_PG;
        vcpu_sregs.cr0 = CR0_PE | CR0_AM | CR0_ET | CR0_PG | CR0_WP; // | CR0_MP | CR0_NE;
        vcpu_sregs.cr3 = VMS.lock().pageTables.GetRoot();
        //vcpu_sregs.cr4 = CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT;
        vcpu_sregs.cr4 = CR4_PAE | CR4_PGE | CR4_OSFXSR | CR4_OSXMMEXCPT | CR4_FSGSBASE;// | CR4_UMIP ;// CR4_PSE | | CR4_SMEP | CR4_SMAP;

        vcpu_sregs.efer = EFER_LME | EFER_LMA | EFER_SCE | EFER_NX;

        vcpu_sregs.idt = kvm_bindings::kvm_dtable {
            base: 0,
            limit: 4095,
            ..Default::default()
        };

        vcpu_sregs.gdt = kvm_bindings::kvm_dtable {
            base: self.gdtAddr,
            limit: 4095,
            ..Default::default()
        };

        self.SetupGDT(&mut vcpu_sregs);
        self.vcpu.set_sregs(&vcpu_sregs).map_err(|e| Error::IOError(format!("io::error is {:?}", e)))?;
        Ok(())
    }

    pub fn Schedule(&self, taskId: TaskId) {
        SHARE_SPACE.scheduler.ScheduleQ(taskId, taskId.Queue());
    }

    pub fn run(&self) -> Result<()> {
        self.setup_long_mode()?;

        let regs: kvm_regs = kvm_regs {
            rflags: KERNEL_FLAGS_SET,
            rip: self.entry,
            rsp: self.topStackAddr,
            rax: 0x11,
            rbx: 0xdd,
            //arg0
            rdi: self.heapStartAddr, // self.pageAllocatorBaseAddr + self.,
            //arg1
            rsi: self.shareSpaceAddr,
            //arg2
            rdx: self.id as u64,
            //arg3
            rcx: VMS.lock().vdsoAddr,
            //arg4
            r8: self.vcpuCnt as u64,
            //arg5
            r9: self.autoStart as u64,
            //rdx:
            //rcx:
            ..Default::default()
        };

        self.vcpu.set_regs(&regs).map_err(|e| Error::IOError(format!("io::error is {:?}", e)))?;


        let mut lastVal: u32 = 0;
        let mut first = true;

        let coreid = core_affinity::CoreId{id: self.id + QUARK_CONFIG.lock().DedicateUring}; // skip core #0 for uring
        core_affinity::set_for_current(coreid);

        info!("start enter guest[{}]: entry is {:x}, stack is {:x}", self.id, self.entry, self.topStackAddr);
        loop {
            if !super::runc::runtime::vm::IsRunning() {
                return Ok(())
            }

            match self.vcpu.run().expect(&format!("kvm virtual cpu[{}] run failed", self.id)) {
                VcpuExit::IoIn(addr, data) => {
                    info!(
                    "[{}]Received an I/O in exit. Address: {:#x}. Data: {:#x}",
                    self.id,
                    addr,
                    data[0],
                    );

                    let vcpu_sregs = self.vcpu.get_sregs().map_err(|e| Error::IOError(format!("io::error is {:?}", e)))?;
                    if vcpu_sregs.cs.dpl != 0x0 { // call from user space
                        panic!("Get VcpuExit::IoIn from guest user space, Abort, vcpu_sregs is {:#x?}", vcpu_sregs)
                    }
                }
                VcpuExit::IoOut(addr, data) => {
                    let vcpu_sregs = self.vcpu.get_sregs().map_err(|e| Error::IOError(format!("io::error is {:?}", e)))?;
                    if vcpu_sregs.cs.dpl != 0x0 { // call from user space
                        panic!("Get VcpuExit::IoOut from guest user space, Abort, vcpu_sregs is {:#x?}", vcpu_sregs)
                    }

                    match addr {
                        qlib::HYPERCALL_IOWAIT => {
                            if !super::runc::runtime::vm::IsRunning() {
                                {
                                    error!("signal debug");
                                    for i in 0..8 {
                                        error!("vcpu[{}] state is {}/{}", i, SHARE_SPACE.GetValue(i, 0), SHARE_SPACE.GetValue(i, 1))
                                    }
                                }

                                return Ok(())
                            }

                            //error!("HYPERCALL_IOWAIT sleeping ...");
                            match KERNEL_IO_THREAD.Wait(&SHARE_SPACE) {
                                Ok(()) => (),
                                Err(Error::Exit) => {
                                    if !super::runc::runtime::vm::IsRunning() {
                                        {
                                            error!("signal debug");
                                            for i in 0..8 {
                                                error!("vcpu[{}] state is {}/{}", i, SHARE_SPACE.GetValue(i, 0), SHARE_SPACE.GetValue(i, 1))
                                            }
                                        }

                                        return Ok(())
                                    }

                                    return Ok(())
                                },
                                Err(e) => {
                                    panic!("KERNEL_IO_THREAD get error {:?}", e);
                                }
                            }
                            //error!("HYPERCALL_IOWAIT waking ...");

                        }
                        qlib::HYPERCALL_URING_WAKE => {
                            let regs = self.vcpu.get_regs().map_err(|e| Error::IOError(format!("io::error is {:?}", e)))?;
                            let idx = regs.rbx as usize;
                            let minComplete = regs.rcx as usize;

                            URING_MGR.lock().Wake(idx, minComplete).expect("qlib::HYPER CALL_URING_WAKE fail");
                        }
                        qlib::HYPERCALL_RELEASE_VCPU => {
                            SyncMgr::WakeShareSpaceReady();
                        }
                        qlib::HYPERCALL_EXIT_VM => {
                            let regs = self.vcpu.get_regs().map_err(|e| Error::IOError(format!("io::error is {:?}", e)))?;
                            let exitCode = regs.rbx as i32;

                            super::print::LOG.lock().Clear();
                            PerfPrint();

                            SetExitStatus(exitCode);

                            //wake up Kernel io thread
                            KERNEL_IO_THREAD.Wakeup(&SHARE_SPACE);

                            //wake up workthread
                            VirtualMachine::WakeAll(&SHARE_SPACE);
                        }

                        qlib::HYPERCALL_PANIC => {
                            let vcpu_regs = self.vcpu.get_regs().unwrap();
                            let addr = vcpu_regs.rbx;
                            let msg = unsafe {
                                &*(addr as *const Print)
                            };

                            eprintln!("Application error: {}", msg.str);
                            ::std::process::exit(1);
                        }

                        qlib::HYPERCALL_WAKEUP_VCPU => {
                            let regs = self.vcpu.get_regs().map_err(|e| Error::IOError(format!("io::error is {:?}", e)))?;
                            let vcpuId = regs.rbx as usize;

                            //error!("HYPERCALL_WAKEUP_VCPU vcpu id is {:x}", vcpuId);
                            SyncMgr::WakeVcpu(vcpuId);
                        }

                        qlib::HYPERCALL_PRINT => {
                            let vcpu_regs = self.vcpu.get_regs().unwrap();
                            let addr = vcpu_regs.rbx;
                            let msg = unsafe {
                                &*(addr as *const Print)
                            };

                            log!("{}", msg.str);
                        }

                        qlib::HYPERCALL_MSG => {
                            let vcpu_regs = self.vcpu.get_regs().unwrap();
                            let data1 = vcpu_regs.rbx;
                            let data2 = vcpu_regs.rcx;
                            let data3 = vcpu_regs.rdi;
                            info!("[{}] get kernel msg [rsp {:x}/rip {:x}]: {:x}, {:x}, {:x}", self.id, vcpu_regs.rsp, vcpu_regs.rip, data1, data2, data3);
                        }

                        qlib::HYPERCALL_OOM => {
                            let vcpu_regs = self.vcpu.get_regs().unwrap();
                            let data1 = vcpu_regs.rbx;
                            let data2 = vcpu_regs.rcx;
                            error!("OOM!!! cpu [{}], size is {:x}, alignment is {:x}", self.id, data1, data2);
                            eprintln!("OOM!!! cpu [{}], size is {:x}, alignment is {:x}", self.id, data1, data2);
                            ::std::process::exit(1);
                        }

                        qlib::HYPERCALL_EXIT => {
                            info!("call in HYPERCALL_EXIT");
                            unsafe { libc::_exit(0) }
                        }

                        qlib::HYPERCALL_U64 => {
                            unsafe {
                                let val = *((data as *const _) as *const u32);
                                if first {
                                    first = false;
                                    lastVal = val
                                } else {
                                    info!("get kernel u64 : 0x{:x}{:x}", lastVal, val);
                                    first = true;
                                }
                            }
                        }

                        qlib::HYPERCALL_GETTIME => {
                            let regs = self.vcpu.get_regs().map_err(|e| Error::IOError(format!("io::error is {:?}", e)))?;
                            let data = regs.rbx;

                            unsafe {
                                let call = &mut *(data as *mut GetTimeCall);

                                let clockId = call.clockId;
                                let ts = Timespec::default();

                                let res = clock_gettime(clockId as clockid_t, &ts as *const _ as u64 as *mut timespec) as i64;

                                if res == -1 {
                                    call.res = errno::errno().0 as i64;
                                } else {
                                    call.res = ts.ToNs()?;
                                }
                            }
                        }

                        qlib::HYPERCALL_VCPU_FREQ => {
                            let regs = self.vcpu.get_regs().map_err(|e| Error::IOError(format!("io::error is {:?}", e)))?;
                            let data = regs.rbx;

                            let freq = self.vcpu.get_tsc_khz().unwrap() * 1000;
                            unsafe {
                                let call = &mut *(data as *mut VcpuFeq);
                                call.res = freq as i64;
                            }
                        }

                        qlib::HYPERCALL_VCPU_YIELD => {
                            use std::{thread, time};

                            let millis10 = time::Duration::from_millis(10);
                            thread::sleep(millis10);
                        }

                        qlib::HYPERCALL_VCPU_DEBUG => {
                            let regs = self.vcpu.get_regs().map_err(|e| Error::IOError(format!("io::error is {:?}", e)))?;
                            let vcpu_sregs = self.vcpu.get_sregs().map_err(|e| Error::IOError(format!("vcpu::error is {:?}", e)))?;
                            error!("[{}] HYPERCALL_VCPU_DEBUG regs is {:#x?}", self.id, regs);
                            error!("sregs is {:#x?}", vcpu_sregs);
                            error!("vcpus is {:#x?}", &SHARE_SPACE.scheduler.VcpuArr);
                            unsafe { libc::_exit(0) }
                        }

                        qlib::HYPERCALL_VCPU_PRINT => {
                            let regs = self.vcpu.get_regs().map_err(|e| Error::IOError(format!("io::error is {:?}", e)))?;
                            error!("[{}] HYPERCALL_VCPU_PRINT regs is {:#x?}", self.id, regs);
                        }

                        qlib::HYPERCALL_QCALL => {
                            self.GuestMsgProcess(&SHARE_SPACE);
                            // last processor in host
                            if SHARE_SPACE.DecrHostProcessor() == 0 {
                                self.GuestMsgProcess(&SHARE_SPACE);
                            }
                        }

                        qlib::HYPERCALL_HCALL => {
                            let regs = self.vcpu.get_regs().map_err(|e| Error::IOError(format!("io::error is {:?}", e)))?;
                            let addr = regs.rbx;

                            let eventAddr = addr as *mut QMsg; // as &mut qlib::Event;
                            let qmsg = unsafe {
                                &mut (*eventAddr)
                            };

                            {
                                let _l = if qmsg.globalLock {
                                    Some(super::GLOCK.lock())
                                } else {
                                    None
                                };

                                qmsg.ret = self.qCall(qmsg.msg);
                            }

                            SHARE_SPACE.IncrHostProcessor();

                            self.GuestMsgProcess(&SHARE_SPACE);
                            // last processor in host
                            if SHARE_SPACE.DecrHostProcessor() == 0 {
                                self.GuestMsgProcess(&SHARE_SPACE);
                            }
                        }

                        qlib::HYPERCALL_VCPU_WAIT => {
                            let regs = self.vcpu.get_regs().map_err(|e| Error::IOError(format!("io::error is {:?}", e)))?;
                            let retAddr = regs.rdi;
                            let ret = self.VcpuWait();
                            if ret == -1 {
                                return Ok(())
                            }

                            unsafe {
                                *(retAddr as * mut u64) = ret as u64;
                            }
                        }

                        _ => info!("Unknow hyper call!!!!! address is {}", addr)
                    }
                }
                VcpuExit::MmioRead(addr, _data) => {
                    info!(
                    "CPU[{}] Received an MMIO Read Request for the address {:#x}.",
                    self.id, addr,
                    );
                }
                VcpuExit::MmioWrite(addr, _data) => {
                    info!(
                    "[{}] Received an MMIO Write Request to the address {:#x}.",
                    self.id,
                    addr,
                    );
                }
                VcpuExit::Hlt => {
                    error!("in hlt....");
                }
                VcpuExit::FailEntry => {
                    info!("get fail entry***********************************");
                    break
                }
                VcpuExit::Exception => {
                    info!("get exception");
                }
                VcpuExit::IrqWindowOpen => {
                    info!("get VcpuExit::IrqWindowOpen");
                    //QueueTimer(&self.vcpu);
                    //&self.vcpu.DisableInterruptWindow();
                }

                r => {
                    let vcpu_sregs = self.vcpu.get_sregs().map_err(|e| Error::IOError(format!("vcpu::error is {:?}", e)))?;
                    let regs = self.vcpu.get_regs().map_err(|e| Error::IOError(format!("vcpu::error is {:?}", e)))?;

                    error!("Panic: CPU[{}] Unexpected exit reason: {:?}, regs is {:#x?}, sregs is {:#x?}",
                        self.id, r, regs, vcpu_sregs);
                    unsafe {
                        libc::exit(0);
                    }
                },
            }
        }

        //let mut vcpu_regs = self.vcpu_fd.get_regs()?;
        Ok(())
    }

    pub fn VcpuWait(&self) -> i64 {
        let sharespace = &SHARE_SPACE;
        while sharespace.scheduler.GlobalReadyTaskCnt() == 0 {
            if !super::runc::runtime::vm::IsRunning() {
                return -1
            }

            {
                sharespace.IncrHostProcessor();
                self.GuestMsgProcess(sharespace);

                defer!({
                    // last processor in host
                    if sharespace.DecrHostProcessor() == 0 {
                        self.GuestMsgProcess(sharespace);
                    }
                });

                for _ in 0..10 {
                    self.GuestMsgProcess(sharespace);
                    //short term workaround, need to change back to unblock my sql scenario.
                    if sharespace.scheduler.GlobalReadyTaskCnt() > 0 {
                        return 0;
                    }

                    match sharespace.scheduler.WaitVcpu(sharespace, self.id, false) {
                        Ok(_) => {}
                        Err(Error::Exit) => return -1,
                        Err(e) => panic!("HYPERCALL_HLT wait fail with error {:?}", e),
                    }

                    //std::thread::yield_now();
                    //std::thread::yield_now();
                }
            }

            if sharespace.scheduler.GlobalReadyTaskCnt() != 0 {
                return 0;
            }
            let ret = sharespace.scheduler.WaitVcpu(sharespace, self.id, true);
            match ret {
                Ok(count) => {
                    return count
                },
                Err(Error::Exit) => return -1,
                Err(e) => panic!("HYPERCALL_HLT wait fail with error {:?}", e),
            }
        }

        return 0;
    }

    pub fn GuestMsgProcess(&self, sharespace: &'static ShareSpace) {
        loop  {
            let msg = sharespace.AQHostOutputPop();

            match msg {
                None => {
                    break
                },
                Some(HostOutputMsg::QCall(addr)) => {
                    let eventAddr = addr as *mut QMsg; // as &mut qlib::Event;
                    let qmsg = unsafe {
                        &mut (*eventAddr)
                    };
                    let currTaskId = qmsg.taskId;

                    {
                        let _l = if qmsg.globalLock {
                            Some(super::GLOCK.lock())
                        } else {
                            None
                        };

                        qmsg.ret = self.qCall(qmsg.msg);
                    }

                    if currTaskId.Addr() != 0 {
                        sharespace.scheduler.ScheduleQ(currTaskId, currTaskId.Queue())
                    }
                }
                Some(msg) => {
                    //error!("qcall msg is {:x?}", &msg);
                    qcall::AQHostCall(msg, sharespace);
                }
            }

        }
    }
}

impl Scheduler {
   pub fn Init(&mut self) {
        for i in 0..self.vcpuCnt {
            self.VcpuArr[i].Init(i);
        }
    }

    pub fn WaitVcpu(&self, sharespace: &ShareSpace, vcpuId: usize, block: bool) -> Result<i64> {
        self.vcpuWaitMask.fetch_or(1<<vcpuId, Ordering::SeqCst);
        defer!(self.vcpuWaitMask.fetch_and(!(1<<vcpuId), Ordering::SeqCst););

        return self.VcpuArr[vcpuId].VcpuWait(sharespace, block);
    }
}

impl CPULocal {
    pub fn Init(&mut self, vcpuId: usize) {
        let epfd = unsafe {
            epoll_create1(0)
        };

        if epfd == -1 {
            panic!("CPULocal::Init {} create epollfd fail, error is {}", self.vcpuId, errno::errno().0);
        }

        let eventfd = unsafe {
            libc::eventfd(0, libc::EFD_CLOEXEC)
        };

        if eventfd < 0 {
            panic!("Vcpu::Init fail...");
        }

        let mut ev = epoll_event {
            events: EVENT_READ as u32 | EPOLLET as u32,
            u64: eventfd as u64
        };

        let ret = unsafe {
            epoll_ctl(epfd, EPOLL_CTL_ADD, eventfd, &mut ev as *mut epoll_event)
        };

        if ret == -1 {
            panic!("CPULocal::Init {} add eventfd fail, error is {}", self.vcpuId, errno::errno().0);
        }

        let mut ev = epoll_event {
            events: EVENT_READ as u32 | EPOLLET as u32,
            u64: FD_NOTIFIER.Epollfd() as u64
        };

        let ret = unsafe {
            epoll_ctl(epfd, EPOLL_CTL_ADD, FD_NOTIFIER.Epollfd(), &mut ev as *mut epoll_event)
        };

        if ret == -1 {
            panic!("CPULocal::Init {} add host epollfd fail, error is {}", self.vcpuId, errno::errno().0);
        }

        let mut uring = URING_MGR.lock();

        uring.Addfd(eventfd).expect("fail to add vcpu eventfd");

        self.eventfd = eventfd;
        self.epollfd = epfd;
        self.vcpuId = vcpuId;
        self.data = 1;
    }

    pub fn VcpuWait(&self, sharespace: &ShareSpace, block: bool) -> Result<i64> {
        let mut events = [epoll_event { events: 0, u64: 0 }; 2];

        let time = if block {
            -1
        } else {
            0
        };

        while sharespace.scheduler.GlobalReadyTaskCnt() == 0 {
            self.ToWaiting(sharespace);
            if sharespace.config.read().AsyncPrint() {
                sharespace.LogFlush(false);
            }

            let nfds = unsafe {
                epoll_wait(self.epollfd, &mut events[0], 2, time)
            };
            self.ToSearch(sharespace);

            if !super::runc::runtime::vm::IsRunning() {
                return Err(Error::Exit)
            }

            if nfds == -1 {
                let err = errno::errno().0;
                return Err(Error::SysError(err))
            }

            let mut wakeVcpu = false;
            let mut hasMsg = false;

            if nfds == 0 {
                return Ok(0)
            }

            if nfds == 2 {
                wakeVcpu = true;
                hasMsg = true;
            } else {
                assert!(nfds == 1);
                let fd = events[0].u64 as i32;
                if fd == self.eventfd { // ask for the vcpu wake up
                    wakeVcpu = true;
                } else {
                    hasMsg = true;
                }
            }

            if hasMsg {
                self.ToRunning(sharespace);
                match sharespace.TryLockEpollProcess() {
                    None => {},
                    Some(_lock) => {
                        FD_NOTIFIER.HostEpollWait();
                    }
                }
                self.ToSearch(sharespace);
            }

            if wakeVcpu {
                if wakeVcpu {
                    let mut data : u64 = 0;
                    let ret = unsafe {
                        libc::read(self.eventfd, &mut data as * mut _ as *mut libc::c_void, 8)
                    };

                    if ret < 0 {
                        panic!("KIOThread::Wakeup fail... eventfd is {}, errno is {}",
                               self.eventfd, errno::errno().0);
                    }
                }

                return Ok(0)
            }
        }

        return Ok(0)
    }

    pub fn Wakeup(&self) {
        let val : u64 = 1;
        let ret = unsafe {
            libc::write(self.eventfd, &val as * const _ as *const libc::c_void, 8)
        };
        if ret < 0 {
            panic!("KIOThread::Wakeup fail...");
        }
    }
}

