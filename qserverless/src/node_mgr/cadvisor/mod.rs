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

pub mod client;
pub mod types;

//{"timestamp":"2023-04-14T21:38:47.455689685Z","num_cores":16,"num_physical_cores":8,"num_sockets":1,"cpu_frequency_khz":4900000,"memory_capacity":33239535616,"memory_by_type":{},"nvm":{"memory_mode_capacity":0,"app direct_mode_capacity":0,"avg_power_budget":0},"hugepages":[{"page_size":1048576,"num_pages":0},{"page_size":2048,"num_pages":4096}],"machine_id":"610151e734a24853a6c94831448197db","system_uuid":"9459a1a8-00c2-0000-0000-000000000000","boot_id":"01d849ca-4053-43b9-9c1c-99350dd1e62d","filesystems":[{"device":"/rootfs/var/lib/docker/overlay2/1ea8f1a6a3e0f5a1dfb5805c2062d79c8a9c0043a1fcf143595b80c7d43881dd/merged/dev/shm","capacity":67108864,"type":"vfs","inodes":4057560,"has_inodes":true},{"device":"/rootfs/run/lock","capacity":5242880,"type":"vfs","inodes":4057560,"has_inodes":true},{"device":"/rootfs/run/snapd/ns","capacity":3323957248,"type":"vfs","inodes":4057560,"has_inodes":true},{"device":"/rootfs/dev/shm","capacity":16619765760,"type":"vfs","inodes":4057560,"has_inodes":true},{"device":"/rootfs/run/user/1000","capacity":3323953152,"type":"vfs","inodes":811512,"has_inodes":true},{"device":"/var/lib/docker/overlay2/1ea8f1a6a3e0f5a1dfb5805c2062d79c8a9c0043a1fcf143595b80c7d43881dd/merged/rootfs/var/lib/docker/overlay2/1ea8f1a6a3e0f5a1dfb5805c2062d79c8a9c0043a1fcf143595b80c7d43881dd/merged/dev","capacity":67108864,"type":"vfs","inodes":4057560,"has_inodes":true},{"device":"/var/lib/docker/overlay2/1ea8f1a6a3e0f5a1dfb5805c2062d79c8a9c0043a1fcf143595b80c7d43881dd/merged/run/user/1000","capacity":3323953152,"type":"vfs","inodes":811512,"has_inodes":true},{"device":"/var/lib/docker/overlay2/1ea8f1a6a3e0f5a1dfb5805c2062d79c8a9c0043a1fcf143595b80c7d43881dd/merged/run/snapd/ns","capacity":3323957248,"type":"vfs","inodes":4057560,"has_inodes":true},{"device":"/dev/shm","capacity":67108864,"type":"vfs","inodes":4057560,"has_inodes":true},{"device":"/dev/nvme0n1p2","capacity":250438021120,"type":"vfs","inodes":15597568,"has_inodes":true},{"device":"/rootfs/var/lib/docker/overlay2/1ea8f1a6a3e0f5a1dfb5805c2062d79c8a9c0043a1fcf143595b80c7d43881dd/merged/dev","capacity":67108864,"type":"vfs","inodes":4057560,"has_inodes":true},{"device":"/run","capacity":3323957248,"type":"vfs","inodes":4057560,"has_inodes":true},{"device":"/run/snapd/ns","capacity":3323957248,"type":"vfs","inodes":4057560,"has_inodes":true},{"device":"overlay_0-50","capacity":250438021120,"type":"vfs","inodes":15597568,"has_inodes":true},{"device":"/dev","capacity":67108864,"type":"vfs","inodes":4057560,"has_inodes":true},{"device":"/var/lib/docker/overlay2/1ea8f1a6a3e0f5a1dfb5805c2062d79c8a9c0043a1fcf143595b80c7d43881dd/merged/rootfs/dev/shm","capacity":16619765760,"type":"vfs","inodes":4057560,"has_inodes":true},{"device":"/var/lib/docker/overlay2/1ea8f1a6a3e0f5a1dfb5805c2062d79c8a9c0043a1fcf143595b80c7d43881dd/merged/rootfs/run","capacity":3323957248,"type":"vfs","inodes":4057560,"has_inodes":true},{"device":"/var/lib/docker/overlay2/1ea8f1a6a3e0f5a1dfb5805c2062d79c8a9c0043a1fcf143595b80c7d43881dd/merged/rootfs/run/lock","capacity":5242880,"type":"vfs","inodes":4057560,"has_inodes":true},{"device":"/var/lib/docker/overlay2/1ea8f1a6a3e0f5a1dfb5805c2062d79c8a9c0043a1fcf143595b80c7d43881dd/merged/rootfs/var/lib/docker/overlay2/1ea8f1a6a3e0f5a1dfb5805c2062d79c8a9c0043a1fcf143595b80c7d43881dd/merged/dev/shm","capacity":67108864,"type":"vfs","inodes":4057560,"has_inodes":true},{"device":"/var/lib/docker/overlay2/1ea8f1a6a3e0f5a1dfb5805c2062d79c8a9c0043a1fcf143595b80c7d43881dd/merged/run","capacity":3323957248,"type":"vfs","inodes":4057560,"has_inodes":true},{"device":"/run/user/1000","capacity":3323953152,"type":"vfs","inodes":811512,"has_inodes":true},{"device":"/var/lib/docker/overlay2/1ea8f1a6a3e0f5a1dfb5805c2062d79c8a9c0043a1fcf143595b80c7d43881dd/merged/dev/shm","capacity":67108864,"type":"vfs","inodes":4057560,"has_inodes":true},{"device":"/rootfs/run","capacity":3323957248,"type":"vfs","inodes":4057560,"has_inodes":true},{"device":"/var/lib/docker/overlay2/1ea8f1a6a3e0f5a1dfb5805c2062d79c8a9c0043a1fcf143595b80c7d43881dd/merged/rootfs/run/user/1000","capacity":3323953152,"type":"vfs","inodes":811512,"has_inodes":true},{"device":"/var/lib/docker/overlay2/1ea8f1a6a3e0f5a1dfb5805c2062d79c8a9c0043a1fcf143595b80c7d43881dd/merged/rootfs/run/snapd/ns","capacity":3323957248,"type":"vfs","inodes":4057560,"has_inodes":true},{"device":"/var/lib/docker/overlay2/1ea8f1a6a3e0f5a1dfb5805c2062d79c8a9c0043a1fcf143595b80c7d43881dd/merged/run/lock","capacity":5242880,"type":"vfs","inodes":4057560,"has_inodes":true},{"device":"overlay","capacity":250438021120,"type":"vfs","inodes":15597568,"has_inodes":true},{"device":"/run/lock","capacity":5242880,"type":"vfs","inodes":4057560,"has_inodes":true},{"device":"/var/lib/docker/overlay2/1ea8f1a6a3e0f5a1dfb5805c2062d79c8a9c0043a1fcf143595b80c7d43881dd/merged/dev","capacity":67108864,"type":"vfs","inodes":4057560,"has_inodes":true}],"disk_map":{"259:0":{"name":"nvme0n1","major":259,"minor":0,"size":256060514304,"scheduler":"none"},"8:0":{"name":"sda","major":8,"minor":0,"size":0,"scheduler":"mq-deadline"},"8:16":{"name":"sdb","major":8,"minor":16,"size":0,"scheduler":"mq-deadline"},"8:32":{"name":"sdc","major":8,"minor":32,"size":0,"scheduler":"mq-deadline"},"8:48":{"name":"sdd","major":8,"minor":48,"size":0,"scheduler":"mq-deadline"}},"network_devices":[{"name":"enp0s31f6","mac_address":"a8:a1:59:94:c2:00","speed":-1,"mtu":1500},{"name":"wlx984827e1809f","mac_address":"98:48:27:e1:80:9f","speed":0,"mtu":1500}],"topology":[{"node_id":0,"memory":33239535616,"hugepages":[{"page_size":1048576,"num_pages":0},{"page_size":2048,"num_pages":4096}],"cores":[{"core_id":0,"thread_ids":[0,8],"caches":[{"size":49152,"type":"Data","level":1},{"size":32768,"type":"Instruction","level":1},{"size":524288,"type":"Unified","level":2}],"socket_id":0},{"core_id":1,"thread_ids":[1,9],"caches":[{"size":49152,"type":"Data","level":1},{"size":32768,"type":"Instruction","level":1},{"size":524288,"type":"Unified","level":2}],"socket_id":0},{"core_id":2,"thread_ids":[10,2],"caches":[{"size":49152,"type":"Data","level":1},{"size":32768,"type":"Instruction","level":1},{"size":524288,"type":"Unified","level":2}],"socket_id":0},{"core_id":3,"thread_ids":[11,3],"caches":[{"size":49152,"type":"Data","level":1},{"size":32768,"type":"Instruction","level":1},{"size":524288,"type":"Unified","level":2}],"socket_id":0},{"core_id":4,"thread_ids":[12,4],"caches":[{"size":49152,"type":"Data","level":1},{"size":32768,"type":"Instruction","level":1},{"size":524288,"type":"Unified","level":2}],"socket_id":0},{"core_id":5,"thread_ids":[13,5],"caches":[{"size":49152,"type":"Data","level":1},{"size":32768,"type":"Instruction","level":1},{"size":524288,"type":"Unified","level":2}],"socket_id":0},{"core_id":6,"thread_ids":[14,6],"caches":[{"size":49152,"type":"Data","level":1},{"size":32768,"type":"Instruction","level":1},{"size":524288,"type":"Unified","level":2}],"socket_id":0},{"core_id":7,"thread_ids":[15,7],"caches":[{"size":49152,"type":"Data","level":1},{"size":32768,"type":"Instruction","level":1},{"size":524288,"type":"Unified","level":2}],"socket_id":0}],"caches":[{"size":16777216,"type":"Unified","level":3}]}],"cloud_provider":"Unknown","instance_type":"Unknown","instance_id":"None"}