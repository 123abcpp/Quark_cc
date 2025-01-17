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

use serde::{Deserialize, Serialize};
use std::fs;

use crate::common::*;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct QletConfig {
    pub nodeName: String,
    pub etcdAddresses: Vec<String>,
    pub nodeIp: String,
    
    pub podMgrPort: u16,
    pub tsotCniPort: u16,
    pub tsotSvcPort: u16,
    pub stateSvcPort: u16,

    pub cidr: String,
    pub stateSvcAddr: Vec<String>,
    pub singleNodeModel: bool,
}

impl QletConfig {
    pub fn Load(path: &str) -> Result<Self> {
        let data = fs::read_to_string(path)?;
        let config : QletConfig = serde_json::from_str(&data)?;
        return Ok(config)
    }
}