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

#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(deref_nullptr)]
#![feature(proc_macro_hygiene)]
#![feature(naked_functions)]
#![allow(bare_trait_objects)]
#![feature(map_first_last)]
#![allow(non_camel_case_types)]
#![feature(llvm_asm)]
#![allow(deprecated)]
#![feature(thread_id_value)]
#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(unused_imports)]
#![feature(core_intrinsics)]

extern crate alloc;
extern crate bit_field;
extern crate core_affinity;
extern crate errno;

#[macro_use]
extern crate serde_derive;
extern crate cache_padded;
extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate clap;

#[macro_use]
extern crate scopeguard;

#[macro_use]
extern crate lazy_static;

extern crate libc;
extern crate spin;
extern crate x86_64;
#[macro_use]
extern crate log;
extern crate caps;
extern crate fs2;
extern crate regex;
extern crate simplelog;
extern crate tabwriter;

#[macro_use]
pub mod print;

#[macro_use]
pub mod asm;
pub mod kernel_def;
pub mod qlib;

pub mod id_mgr;
pub mod rdma;
pub mod rdma_agent;
pub mod rdma_channel;
pub mod rdma_conn;
pub mod rdma_ctrlconn;
pub mod rdma_srv;

use crate::rdma_srv::RDMA_CTLINFO;
use crate::rdma_srv::RDMA_SRV;

use self::qlib::ShareSpaceRef;
use std::collections::HashMap;
use std::io;
use std::io::prelude::*;
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::os::unix::io::{AsRawFd, RawFd};
pub static SHARE_SPACE: ShareSpaceRef = ShareSpaceRef::New();
use crate::qlib::rdma_share::*;
use crate::rdma::RDMA;
use local_ip_address::list_afinet_netifas;
use local_ip_address::local_ip;
use qlib::linux_def::*;
use qlib::socket_buf::SocketBuff;
use qlib::unix_socket::UnixSocket;
use rdma_channel::RDMAChannel;
use rdma_conn::*;
use rdma_ctrlconn::Node;
use spin::Mutex;
use std::io::Error;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::{env, mem, ptr, thread, time};
//use qlib::range::{IdMgr, GapMgr};
use id_mgr::IdMgr;

#[allow(unused_macros)]
macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        let res = unsafe { libc::$fn($($arg, )*) };
        if res == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

#[repr(C)]
#[repr(packed)]
#[derive(Default, Copy, Clone, Debug)]
pub struct EpollEvent {
    pub Events: u32,
    pub U64: u64,
}

const READ_FLAGS: i32 = libc::EPOLLET | libc::EPOLLIN;
//const READ_FLAGS: i32 = libc::EPOLLONESHOT | libc::EPOLLIN | libc::EPOLLOUT;
const WRITE_FLAGS: i32 = libc::EPOLLET | libc::EPOLLOUT;
//const WRITE_FLAGS: i32 = libc::EPOLLONESHOT | libc::EPOLLIN | libc::EPOLLOUT;

const READ_WRITE_FLAGS: i32 = libc::EPOLLET | libc::EPOLLOUT | libc::EPOLLIN;

pub enum FdType {
    UnixDomainSocketServer,
    UnixDomainSocketConnect,
    TCPSocketServer,
    TCPSocketConnect(u32),
    RDMACompletionChannel,
}

fn main() {
    println!("RDMA Service is starting!");
    let x = RDMA_SRV.agentIdMgr.lock().AllocId().unwrap();
    println!("x is: {}", x);
}

fn id_mgr_test() {
    // let mut idMgr: IdMgr<u32> = IdMgr::Init(0, 1000);
    // let mut gapMgr = GapMgr::New(0, 100);
    // let x = gapMgr.AllocAfter(0, 1, 0).unwrap();
    // let y = gapMgr.AllocAfter(1, 1, 0).unwrap();
    // println!("x: {}, y: {}", x, y);

    // let x1 = idMgr.AllocId().unwrap();
    // let y1 = idMgr.AllocId().unwrap();
    // let y2 = idMgr.AllocId().unwrap();
    // idMgr.Remove(y1);
    // let y4 = idMgr.AllocId().unwrap();
    // println!("x1: {}, y1: {}, y2: {}, y4: {}", x1, y1, y2, y4);
    let mut idMgr = IdMgr::Init(1, 1000);
    let x1 = idMgr.AllocId().unwrap();
    let x2 = idMgr.AllocId().unwrap();
    let x3 = idMgr.AllocId().unwrap();
    let x4 = idMgr.AllocId().unwrap();
    println!("x1: {}, x2: {}, x3: {}, x4: {}", x1, x2, x3, x4);
    idMgr.Remove(x3);
    idMgr.Remove(x2);
    let x3 = idMgr.AllocId().unwrap();
    println!("x1: {}, x2: {}, x3: {}, x4: {}", x1, x2, x3, x4);
    idMgr.Remove(x2);
    idMgr.Remove(x4);
    let x2 = idMgr.AllocId().unwrap();

    println!("x1: {}, x2: {}, x3: {}, x4: {}", x1, x2, x3, x4);
}

fn share_client_region() {
    let path = "/home/qingming/rdma_srv";
    let fd = unsafe {
        libc::memfd_create(
            "Server memfd".as_ptr() as *const i8,
            libc::MFD_ALLOW_SEALING,
        )
    };
    let size = mem::size_of::<qlib::rdma_share::ClientShareRegion>();
    let ret = unsafe { libc::ftruncate(fd, size as i64) };
    let addr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            //libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };

    println!("addr: 0x{:x}", addr as u64);
    let eventAddr = addr as *mut ClientShareRegion; // as &mut qlib::Event;
    let clientShareRegion = unsafe { &mut (*eventAddr) };
    let readBufAtomsAddr = &clientShareRegion.ioMetas[0].readBufAtoms as *const _ as u64;
    println!("readBufAtomsAddr: 0x{:x}", readBufAtomsAddr);
    let writeBufAtomsAddr = &clientShareRegion.ioMetas[0].writeBufAtoms as *const _ as u64;
    println!("readBufAtomsAddr: 0x{:x}", writeBufAtomsAddr);
    let sockBuf = SocketBuff::InitWithShareMemory(
        MemoryDef::DEFAULT_BUF_PAGE_COUNT,
        &clientShareRegion.ioMetas[0].readBufAtoms as *const _ as u64,
        &clientShareRegion.ioMetas[0].writeBufAtoms as *const _ as u64,
        &clientShareRegion.ioMetas[0].consumeReadData as *const _ as u64,
        &clientShareRegion.iobufs[0].read as *const _ as u64,
        &clientShareRegion.iobufs[0].write as *const _ as u64,
    );

    let srv_sock = UnixSocket::NewServer(path).unwrap();
    let conn_sock = UnixSocket::Accept(srv_sock.as_raw_fd()).unwrap();
    let c = sockBuf.AddConsumeReadData(6);
    println!(
        "conn_sock: {}, srv fd: {}, consumeReadData: {}",
        conn_sock.as_raw_fd(),
        fd,
        c
    );
    conn_sock.SendFd(fd).unwrap();
    let ten_millis = time::Duration::from_secs(2);
    let now = time::Instant::now();

    thread::sleep(ten_millis);
    println!("exit");
}
fn test() {
    let a = AtomicU32::new(1);
    let addr = &a as *const _ as u64;
    let b = &a;
    println!(
        "a's address is: 0x{:x}, ab's address: {:p}, b's address: {:p}",
        addr, b, &b
    );
    let x = b.load(Ordering::Relaxed);
    println!("1 x is {}", x);
    b.store(2, Ordering::Release);
    let x = b.load(Ordering::Relaxed);
    println!("2 x is {}", x);

    let size = mem::size_of::<qlib::rdma_share::ClientShareRegion>();
    println!("size is {}", size);
    let addr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };

    println!("addr: 0x{:x}", addr as u64);
    let eventAddr = addr as *mut ClientShareRegion; // as &mut qlib::Event;
    let clientShareRegion = unsafe { &mut (*eventAddr) };
    let readBufAtomsAddr = &clientShareRegion.ioMetas[0].readBufAtoms as *const _ as u64;
    println!("readBufAtomsAddr: 0x{:x}", readBufAtomsAddr);
    let writeBufAtomsAddr = &clientShareRegion.ioMetas[0].writeBufAtoms as *const _ as u64;
    println!("readBufAtomsAddr: 0x{:x}", writeBufAtomsAddr);
    let sockBuf = SocketBuff::InitWithShareMemory(
        MemoryDef::DEFAULT_BUF_PAGE_COUNT,
        &clientShareRegion.ioMetas[0].readBufAtoms as *const _ as u64,
        &clientShareRegion.ioMetas[0].writeBufAtoms as *const _ as u64,
        &clientShareRegion.ioMetas[0].consumeReadData as *const _ as u64,
        &clientShareRegion.iobufs[0].read as *const _ as u64,
        &clientShareRegion.iobufs[0].write as *const _ as u64,
    );

    let consumeReadData = sockBuf.AddConsumeReadData(6);
    println!("consumeReadData: {}", consumeReadData);
    println!(
        "ShareRegion size is: {}",
        mem::size_of::<qlib::rdma_share::ShareRegion>()
    );
    println!(
        "ClientShareRegion size is: {}",
        mem::size_of::<qlib::rdma_share::ClientShareRegion>()
    );
    println!(
        "RingQueue<RDMAResp> size is: {}",
        mem::size_of::<qlib::rdma_share::RingQueue<RDMAResp>>()
    );
    println!(
        "RingQueue<RDMAReq> size is: {}",
        mem::size_of::<qlib::rdma_share::RingQueue<RDMAReq>>()
    );
    println!(
        "IOMetas size is: {}",
        mem::size_of::<qlib::rdma_share::IOMetas>()
    );
    println!(
        "IOBuf size is: {}",
        mem::size_of::<qlib::rdma_share::IOBuf>()
    );

    // let shareRegionSize = mem::size_of::<qlib::rdma_share::ShareRegion>();
    // let addr = unsafe { libc::malloc(shareRegionSize) };
    // println!("addr: 0x{:x}", addr as u64);
    // let eventAddr = addr as *mut ShareRegion; // as &mut qlib::Event;
    // let shareRegion = unsafe { &mut (*eventAddr) };
    // RDMA_SRV.shareRegion = shareRegion;
    // shareRegion.srvBitmap.store(64, Ordering::SeqCst);
    // println!(
    //     "srvBitmap: {}",
    //     RDMA_SRV
    //     .shareRegion
    //         .srvBitmap
    //         .load(Ordering::Relaxed)
    // );
}

fn main_backup() -> io::Result<()> {
    println!("RDMA Service is starting!");
    println!("size of RDMAConn: {}", mem::size_of::<RDMAConn>());
    //TODO: make devicename and port configurable
    RDMA.Init("", 1);
    println!(
        "size is: {}",
        mem::size_of::<qlib::rdma_share::ShareRegion>()
    );

    // hashmap for file descriptors so that different handling can be dispatched.
    let mut fds: HashMap<i32, FdType> = HashMap::new();

    let epoll_fd = epoll_create().expect("can create epoll queue");
    let mut events: Vec<EpollEvent> = Vec::with_capacity(1024);

    let args: Vec<_> = env::args().collect();
    let server_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    println!("server_fd is {}", server_fd);
    unblock_fd(server_fd);
    fds.insert(server_fd, FdType::TCPSocketServer);
    epoll_add(epoll_fd, server_fd, read_write_event(server_fd as u64))?;

    unsafe {
        let mut serv_addr: libc::sockaddr_in = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: 8888u16.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_be_bytes([0, 0, 0, 0]).to_be(),
            },
            sin_zero: mem::zeroed(),
        };

        if args.len() > 1 {
            serv_addr = libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: 8889u16.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_be_bytes([0, 0, 0, 0]).to_be(),
                },
                sin_zero: mem::zeroed(),
            };
        }

        let result = libc::bind(
            server_fd,
            &serv_addr as *const libc::sockaddr_in as *const libc::sockaddr,
            mem::size_of_val(&serv_addr) as u32,
        );
        if result < 0 {
            libc::close(server_fd);
            panic!("last OS error: {:?}", Error::last_os_error());
        }

        libc::listen(server_fd, 128);
    }

    let local_ip = get_local_ip();
    println!("litener sock fd is {}", server_fd);

    let cur_timestamp = RDMA_CTLINFO.nodes.lock().get(&local_ip).unwrap().timestamp;
    println!("timestamp is {}", cur_timestamp);

    // connect to other RDMA service on nodes which timestamp is bigger
    // for (ipAddr, node) in RDMA_CTLINFO.nodes.lock().iter() {
    //     if cur_timestamp < node.timestamp {
    if args.len() > 1 {
        let node = Node {
            //ipAddr: u32::from(Ipv4Addr::from_str("6.1.16.172").unwrap()),
            ipAddr: u32::from(Ipv4Addr::from_str("172.16.1.6").unwrap()).to_be(),
            timestamp: 0,
            subnet: u32::from(Ipv4Addr::from_str("172.16.1.0").unwrap()),
            netmask: u32::from(Ipv4Addr::from_str("255.255.255.0").unwrap()),
        };
        let sock_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        println!("sock_fd is {}", sock_fd);
        unblock_fd(sock_fd);
        fds.insert(sock_fd, FdType::TCPSocketConnect(node.ipAddr));
        epoll_add(epoll_fd, sock_fd, read_write_event(sock_fd as u64))?;

        println!("new conn");
        let controlRegionId = RDMA_SRV.controlBufIdMgr.lock().AllocId().unwrap() as usize; // TODO: should handle no space issue.
        let sockBuf = Arc::new(SocketBuff::InitWithShareMemory(
            MemoryDef::DEFAULT_BUF_PAGE_COUNT,
            &RDMA_SRV.controlRegion.ioMetas[controlRegionId].readBufAtoms as *const _ as u64,
            &RDMA_SRV.controlRegion.ioMetas[controlRegionId].writeBufAtoms as *const _ as u64,
            &RDMA_SRV.controlRegion.ioMetas[controlRegionId].consumeReadData as *const _ as u64,
            &RDMA_SRV.controlRegion.iobufs[controlRegionId].read as *const _ as u64,
            &RDMA_SRV.controlRegion.iobufs[controlRegionId].write as *const _ as u64,
        ));

        let rdmaConn = RDMAConn::New(
            sock_fd,
            sockBuf.clone(),
            RDMA_SRV.keys[controlRegionId / 16][1],
        );
        let rdmaControlChannel = RDMAChannel::New(
            0,
            0,
            RDMA_SRV.keys[controlRegionId / 16][0],
            RDMA_SRV.keys[controlRegionId / 16][1],
            sockBuf.clone(),
            rdmaConn.clone(),
        );

        let rdmaControlChannel = RDMAControlChannel1::New((*rdmaControlChannel.clone()).clone());

        //*rdmaConn.ctrlChan.lock() = RDMAControlChannel::New((*rdmaControlChannel.clone()).clone());
        *rdmaConn.ctrlChan.lock() = rdmaControlChannel.clone();
        for qp in rdmaConn.GetQueuePairs() {
            RDMA_SRV
                .controlChannels
                .lock()
                .insert(qp.qpNum(), rdmaControlChannel.clone());
        }

        println!("before insert");
        RDMA_SRV.conns.lock().insert(node.ipAddr, rdmaConn.clone());
        println!("after insert");
        unsafe {
            let serv_addr: libc::sockaddr_in = libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: 8888u16.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: node.ipAddr,
                },
                sin_zero: mem::zeroed(),
            };
            let ret = libc::connect(
                sock_fd,
                &serv_addr as *const libc::sockaddr_in as *const libc::sockaddr,
                mem::size_of_val(&serv_addr) as u32,
            );

            println!("ret is {}, error: {}", ret, Error::last_os_error());
        }
        // }
    }
    // }

    loop {
        events.clear();
        println!("in loop");
        let res = match syscall!(epoll_wait(
            epoll_fd,
            events.as_mut_ptr() as *mut libc::epoll_event,
            1024,
            -1 as libc::c_int,
        )) {
            Ok(v) => v,
            Err(e) => panic!("error during epoll wait: {}", e),
        };

        unsafe { events.set_len(res as usize) };

        println!("res is: {}", res);

        for ev in &events {
            //print!("u64: {}, events: {:x}", ev.U64, ev.Events);
            let event_data = fds.get(&(ev.U64 as i32));
            match event_data {
                Some(FdType::TCPSocketServer) => {
                    let stream_fd;
                    let mut cliaddr: libc::sockaddr_in = unsafe { mem::zeroed() };
                    let mut len = mem::size_of_val(&cliaddr) as u32;
                    unsafe {
                        stream_fd = libc::accept(
                            ev.U64 as i32,
                            &mut cliaddr as *mut libc::sockaddr_in as *mut libc::sockaddr,
                            &mut len,
                        );
                    }
                    unblock_fd(stream_fd);
                    println!("stream_fd is: {}", stream_fd);

                    let peerIpAddrU32 = cliaddr.sin_addr.s_addr;
                    fds.insert(stream_fd, FdType::TCPSocketConnect(peerIpAddrU32));
                    let controlRegionId =
                        RDMA_SRV.controlBufIdMgr.lock().AllocId().unwrap() as usize; // TODO: should handle no space issue.
                    let sockBuf = Arc::new(SocketBuff::InitWithShareMemory(
                        MemoryDef::DEFAULT_BUF_PAGE_COUNT,
                        &RDMA_SRV.controlRegion.ioMetas[controlRegionId].readBufAtoms as *const _
                            as u64,
                        &RDMA_SRV.controlRegion.ioMetas[controlRegionId].writeBufAtoms as *const _
                            as u64,
                        &RDMA_SRV.controlRegion.ioMetas[controlRegionId].consumeReadData as *const _
                            as u64,
                        &RDMA_SRV.controlRegion.iobufs[controlRegionId].read as *const _ as u64,
                        &RDMA_SRV.controlRegion.iobufs[controlRegionId].write as *const _ as u64,
                    ));

                    let rdmaConn = RDMAConn::New(
                        stream_fd,
                        sockBuf.clone(),
                        RDMA_SRV.keys[controlRegionId / 16][1],
                    );
                    let rdmaControlChannel = RDMAChannel::New(
                        0,
                        0,
                        RDMA_SRV.keys[controlRegionId / 16][0],
                        RDMA_SRV.keys[controlRegionId / 16][1],
                        sockBuf.clone(),
                        rdmaConn.clone(),
                    );
                    let rdmaControlChannel =
                        RDMAControlChannel1::New((*rdmaControlChannel.clone()).clone());

                    //*rdmaConn.ctrlChan.lock() = RDMAControlChannel::New((*rdmaControlChannel.clone()).clone());
                    *rdmaConn.ctrlChan.lock() = rdmaControlChannel.clone();
                    for qp in rdmaConn.GetQueuePairs() {
                        RDMA_SRV
                            .controlChannels
                            .lock()
                            .insert(qp.qpNum(), rdmaControlChannel.clone());
                    }

                    RDMA_SRV.conns.lock().insert(peerIpAddrU32, rdmaConn);
                    epoll_add(epoll_fd, stream_fd, read_write_event(stream_fd as u64))?;
                    println!("add stream fd");
                }
                Some(FdType::TCPSocketConnect(ipAddr)) => match RDMA_SRV.conns.lock().get(ipAddr) {
                    Some(rdmaConn) => {
                        rdmaConn.Notify(ev.Events as u64);
                    }
                    _ => {
                        panic!("no RDMA connection for {} found!", ipAddr)
                    }
                },
                Some(FdType::RDMACompletionChannel) => {
                    println!("xx");
                }
                Some(FdType::UnixDomainSocketConnect) => {
                    println!("xx");
                }
                Some(FdType::UnixDomainSocketServer) => {
                    println!("xx");
                }
                None => {
                    //panic!("unexpected fd {} found", ev.U64);
                }
            }
        }
    }
}

fn get_local_ip() -> u32 {
    let my_local_ip = local_ip().unwrap();

    // println!("This is my local IP address: {:?}", my_local_ip);

    let network_interfaces = list_afinet_netifas().unwrap();

    for (name, ip) in network_interfaces.iter() {
        //println!("{}:\t{:?}", name, ip);
    }

    return u32::from(Ipv4Addr::from_str("172.16.1.6").unwrap());
}

fn epoll_create() -> io::Result<RawFd> {
    let fd = syscall!(epoll_create1(0))?;
    if let Ok(flags) = syscall!(fcntl(fd, libc::F_GETFD)) {
        let _ = syscall!(fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC));
    }

    Ok(fd)
}

fn read_event(key: u64) -> libc::epoll_event {
    libc::epoll_event {
        events: READ_FLAGS as u32,
        u64: key,
    }
}

fn write_event(key: u64) -> libc::epoll_event {
    libc::epoll_event {
        events: WRITE_FLAGS as u32,
        u64: key,
    }
}

fn read_write_event(key: u64) -> libc::epoll_event {
    libc::epoll_event {
        events: READ_WRITE_FLAGS as u32,
        u64: key,
    }
}

fn close(fd: RawFd) {
    let _ = syscall!(close(fd));
}

fn epoll_add(epoll_fd: RawFd, fd: RawFd, mut event: libc::epoll_event) -> io::Result<()> {
    syscall!(epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, fd, &mut event))?;
    Ok(())
}

fn epoll_modify(epoll_fd: RawFd, fd: RawFd, mut event: libc::epoll_event) -> io::Result<()> {
    syscall!(epoll_ctl(epoll_fd, libc::EPOLL_CTL_MOD, fd, &mut event))?;
    Ok(())
}

fn epoll_delete(epoll_fd: RawFd, fd: RawFd) -> io::Result<()> {
    syscall!(epoll_ctl(
        epoll_fd,
        libc::EPOLL_CTL_DEL,
        fd,
        std::ptr::null_mut()
    ))?;
    Ok(())
}

fn unblock_fd(fd: i32) {
    unsafe {
        let flags = libc::fcntl(fd, Cmd::F_GETFL, 0);
        let ret = libc::fcntl(fd, Cmd::F_SETFL, flags | Flags::O_NONBLOCK);
        assert!(ret == 0, "UnblockFd fail");
    }
}
