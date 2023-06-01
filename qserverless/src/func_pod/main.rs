// Copyright (c) 2021 Quark Container Authors / 2014 The Kubernetes Authors
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
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

#[macro_use]
extern crate log;

pub mod func_def;
pub mod func_mgr;
pub mod funcagent_client;
pub mod funcall_mgr;

use funcagent_client::FuncAgentClient;
use once_cell::sync::OnceCell;

use qobjs::common::*;

use crate::funcall_mgr::*;

lazy_static::lazy_static! {
    pub static ref FUNC_CALL_MGR: FuncCallMgr = {
        FuncCallMgr::Init()
    };
}

pub static FUNC_AGENT_CLIENT: OnceCell<FuncAgentClient> = OnceCell::new();

#[tokio::main]
async fn main() -> Result<()> {
    println!("test 1");
    log4rs::init_file("fp_logging_config.yaml", Default::default()).unwrap();
    println!("test 1 dddd");
    error!("test 1");
    FUNC_AGENT_CLIENT.set(FuncAgentClient::Init("http://127.0.0.1:8892").await?).unwrap();
    println!("test 2");
    FUNC_CALL_MGR.Process().await?;
    println!("test 3");
    
    return Ok(());
}