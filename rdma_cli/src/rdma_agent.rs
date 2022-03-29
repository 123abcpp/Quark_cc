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
use std::collections::HashSet;

use super::qlib::rdma_share::*;

pub struct RDMAAgentIntern {
    pub id: u32,

    // client id passed when initialize RDMASvcCli, can use container id for container.
    pub clientId: String,

    // the unix socket fd between rdma client and RDMASrv
    pub sockfd: i32,

    // the memfd share memory with rdma client
    pub client_memfd: i32,

    // the eventfd which send notification to client
    pub client_eventfd: i32,

    // the memory region shared with client
    pub shareMemRegion: MemRegion,

    pub shareRegion: &'static mut ClientShareRegion,

    pub usedIoIndexes: HashSet<u32>,

    // TODO: indexes allocated for io buffer.
}

pub struct RDMAAgent(Arc<RDMAAgentIntern>);
