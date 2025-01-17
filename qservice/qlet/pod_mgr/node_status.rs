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

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use qshare::config::NodeConfiguration;
use qshare::node::*;

use qshare::common::*;
use qshare::consts::*;
use qshare::node::Node;
use qshare::node::NodeCondition;

use super::runtime::k8s_quantity::QuarkResource;
use super::CADVISOR_PROVIDER;
use super::RUNTIME_MGR;
use super::cadvisor::client::NodeCAdvisorInfo;
use super::qnode::NETWORK_PROVIDER;
use super::qnode::QuarkNode;
use super::qpod::PodState;

// NodeReady means kubelet is healthy and ready to accept pods.
pub const NodeReady: &str = "Ready";
// NodeMemoryPressure means the kubelet is under pressure due to insufficient available memory.
pub const NodeMemoryPressure: &str = "MemoryPressure";
// NodeDiskPressure means the kubelet is under pressure due to insufficient available disk.
pub const NodeDiskPressure: &str = "DiskPressure";
// NodePIDPressure means the kubelet is under pressure due to insufficient available PID.
pub const NodePIDPressure: &str = "PIDPressure";
// NodeNetworkUnavailable means that network for the node is not correctly configured.
pub const NodeNetworkUnavailable: &str = "NetworkUnavailable";

// These are the valid phases of node.

// NodePending means the node has been created/added by the system, but not configured.
pub const NodePending : &str = "Pending";
// NodeRunning means the node has been configured and has Kubernetes components running.
pub const NodeRunning : &str = "Running";
// NodeTerminated means the node has been removed from the cluster.
pub const NodeTerminated : &str = "Terminated";

pub fn UpdateNodeAddress(node: &mut Node) -> Result<NodeCondition> {
    let addresses = NETWORK_PROVIDER.GetNetAddress();
    if addresses.len() == 0 {
        return Err(Error::CommonError("can't get local v4 ip address".to_string()));
    }

    node.status.addresses = addresses;

    let currentTime = SystemTime::now();
    let condition = NodeCondition {
        type_: NodeNetworkUnavailable.to_string(),
        status: ConditionFalse.to_string(),
        reason: Some("Node network initialized".to_owned()),
        message: Some("Node network initialized".to_owned()),
        last_heartbeat_time: Some(currentTime.clone()),
        last_transition_time: Some(currentTime.clone()),
    };

    return Ok(condition);
}

pub async fn UpdateNodeReadyStatus() -> Result<NodeCondition> {
    let status = RUNTIME_MGR.get().unwrap().GetRuntimeStatus().await?;
    let currentTime = SystemTime::now();

	let mut networkReady = false;
	let mut runtimeReady = false;
    
    for v in &status.conditions {
        if &v.r#type == "RuntimeReady" && v.status {
            networkReady = true;
        }

        if &v.r#type == "NetworkReady" && v.status {
            runtimeReady = true;
        }
    }

    let condition;
    if runtimeReady && networkReady {
        condition = NodeCondition {
            type_: NodeReady.to_string(),
            status: ConditionTrue.to_string(),
            reason: Some("Node runtime ready".to_owned()),
            message: Some("Node runtime ready".to_owned()),
            last_heartbeat_time: Some(currentTime.clone()),
            last_transition_time: Some(currentTime.clone()),
        }
    } else {
        condition = NodeCondition {
            type_: NodeReady.to_string(),
            status: ConditionTrue.to_string(),
            reason: Some("Node runtime not ready".to_owned()),
            message: Some("Node runtime not ready".to_owned()),
            last_heartbeat_time: Some(currentTime.clone()),
            last_transition_time: Some(currentTime.clone()),
        }
    }

    return Ok(condition);
}

pub async fn SetNodeStatus(node: &QuarkNode) -> Result<()> {
    let mut conditions = BTreeMap::new();

    let condition = UpdateNodeAddress(&mut *node.node.lock().unwrap())?;
    conditions.insert(condition.type_.clone(), condition);

    UpdateNodeCapacity(&node.nodeConfig, &mut *node.node.lock().unwrap())?;

    let condition = UpdateNodeReadyStatus().await?;
    conditions.insert(condition.type_.clone(), condition);

    // todo: ...
    /* 
    	condition, err = UpdateNodeMemoryStatus(dependencies.MemoryManager, node.V1Node)
	if err != nil {
		errs = append(errs, errors.New("can not update memory resource status"))
	}
	conditions[condition.Type] = condition

	condition, err = UpdateNodeCPUStatus(dependencies.CPUManager, node.V1Node)
	if err != nil {
		errs = append(errs, errors.New("can not update cpu resource status"))
	}
	conditions[condition.Type] = condition

    	condition, err = UpdateNodeVolumeStatus(dependencies.VolumeManager, node.V1Node)
	if err != nil {
		errs = append(errs, errors.New("can not update volume resource status"))
	}
	conditions[condition.Type] = condition
    */

    let currentTime = SystemTime::now();
    conditions.insert(NodeReady.to_string(), NodeCondition {
        type_: NodeReady.to_string(),
        status: ConditionTrue.to_string(),
        reason: Some("NodeRuntime Ready".to_owned()),
        message: Some("Node is ready to get pod".to_owned()),
        last_heartbeat_time: Some(currentTime.clone()),
        last_transition_time: Some(currentTime.clone()),
    });

    MergeNodeConditions(&mut *node.node.lock().unwrap(), &mut conditions);

    return Ok(())
}

pub fn UpdateNodeCapacity(nodeConfig: &NodeConfiguration, node: &mut Node) -> Result<()> {
    let info = CADVISOR_PROVIDER.get().unwrap().CAdvisorInfo();
    
    let status = &mut node.status;
    let nodeinfo = &mut status.node_info;
    nodeinfo.operating_system = "linux".to_string();
    nodeinfo.architecture = "amd64".to_string();
    nodeinfo.kernel_version = info.versionInfo.KernelVersion.clone();
    nodeinfo.os_image = info.versionInfo.ContainerOsVersion.clone();

    nodeinfo.machine_id = info.machineInfo.MachineID.clone();
    nodeinfo.system_uuid = info.machineInfo.SystemUUID.clone();
    nodeinfo.boot_id = info.machineInfo.BootID.clone();


    let map = ResourceListFromMachineInfo(&info);

    {
        let capacity = &mut status.allocatable;
        for (rname, rCap) in &map {
            capacity.insert(rname.to_string(), rCap.clone());
        }
    }

    let capacity = &mut status.capacity;
    
    for (rname, rCap) in map {
        capacity.insert(rname, rCap);
    }

    if nodeConfig.PodsPerCore > 0 {
        let resourcePods = (info.machineInfo.NumCores * nodeConfig.PodsPerCore) as i64;
        let resourcePods = resourcePods.min(nodeConfig.MaxPods as i64);
        capacity.insert("pods".to_string(), Quantity(resourcePods));
    } else {
        capacity.insert("pods".to_string(), Quantity(nodeConfig.MaxPods as i64));
    }

    return Ok(())
}

pub fn ResourceListFromMachineInfo(info: &Arc<NodeCAdvisorInfo>) -> BTreeMap<String, Quantity> {
    let mut map = BTreeMap::new();
    map.insert(ResourceCPU.to_string(), Quantity(info.machineInfo.NumCores as i64 * 1000));
    map.insert(ResourceMemory.to_string(), Quantity(info.machineInfo.MemoryCapacity as i64));
    return map;
}

pub fn MergeNodeConditions(node: &mut Node, condition: &mut BTreeMap<String, NodeCondition>) {
    let conditions = &mut node.status.conditions;
    let count = conditions.len();
    for i in 0..count {
        let oldCondition = &mut conditions[i];
        if let Some(updatedCondition) = condition.remove(&oldCondition.type_.clone()) {
            oldCondition.last_heartbeat_time = updatedCondition.last_heartbeat_time.clone();
            if oldCondition.status != updatedCondition.status {
                *oldCondition = updatedCondition.clone();
            }
        }
    }

    for (_, v) in condition {
        conditions.push(v.clone());
    }
}

pub fn IsNodeStatusReady(node: &QuarkNode) -> bool {
    // check node capacity and allocatable are set
	let resource = QuarkResource::New(&node.node.lock().unwrap().status.allocatable);

    let cpuReady = resource.cpu > 0;
    let memReady = resource.memory > 0;
    let nodeConditionReady = IsNodeCondtionReady(&*node.node.lock().unwrap());

    let mut daemonReady = true;
    for (_, v) in &*node.pods.lock().unwrap() {
        let state = v.PodState();
        let pod = v.lock().unwrap();
        if pod.isDaemon {
            daemonReady = daemonReady && state == PodState::Running;
        }
    }

    return cpuReady && memReady && daemonReady && nodeConditionReady;
}

pub fn IsNodeCondtionReady(node: &Node) -> bool {
    for v in &node.status.conditions {
        if &v.type_ == NodeReady && &v.status == ConditionTrue {
            return true;
        }
    }

    return false;
}

pub fn IsNodeRunning(node: &Node) -> bool {
    return node.status.phase == NodeRunning.to_string();
}