
# IO-TCP

## Preliminaries

### DPDK
### host-side
Download DPDK-20.05 from Github(https://github.com/DPDK/dpdk.git) (mtcp doesn't support later version of DPDK where target specified build is depreciated.)
Please check that CONFIG_RTE_LIBRTE_MLX5_PMD option has been enabled in dpdk/config/common_base which is disabled by default.
```
cd ./IO-TCP/mtcp_accelstorage
./setup_mtcp_dpdk_env.sh [dpdk path] (i.e. /home/taehyun/dpdk/)
```
In DPDK setup prompt, select a corresponding target. (i.e. x86_64-native-linuxapp-gcc)

### NIC-side
Build DPDK-20.05 with usertools/dpdk-setup.sh
 

### SmartNIC OS
Mellanox Bluefield 2
5.4.31-mlnx.32.gd2bee6f

### NVMe target offloading
To enable your NIC directly read and write SSDs attached on the host server
See instructions in [`doc/NVMe_target_offloading.md`]
(doc/NVMe_target_offloading.md).

### Network setting
Set your NIC with the separated_host mode and set an appropriate IP address
See details in https://support.mellanox.com/s/article/BlueField-SmartNIC-Modes

### Mellanox OFED
Install Mellanox OFED on both the host and the NIC
Host
```
cd MLNX_OFED_LINUX-5.3-1.0.0.1-rhel7.6alternate-aarch64/
./mlnxofedinstall  --dpdk --upstream-libs --force --add-kernel-support
dracut -f
```

NIC
```
./5-1_install_dependency_for_smartnic.sh
cd ../
cd MLNX_OFED_LINUX-5.3-1.0.0.1-rhel7.6alternate-aarch64/
./mlnxofedinstall  --dpdk --bluefield --with-nvmf --upstream-libs --force --add-kernel-support
dracut -f
```

### Other dependencies
Install 
```
./5-1_install_dependency_for_smartnic.sh
```
```c
yum install  libgmp3-dev

apt-get install  libgmp3-dev
```

## Install

### Host side

[mtcp_accelstorage](mtcp_accelstorage): Modified mtcp project.
```
cd mtcp_accelstorage
autoconf
./configure --with-dpdk-lib=[DPDK target path] (i.e. /home/taehyun/dpdk/x86_64-native-linuxapp-gcc/)
```
set RTE_SDK and RTE_TARGET
```
export RTE_SDK=[DPDK installation path] (i.e. /home/username/dpdk-20.05)
export RTE_TARGET=[DPDK target environment] (i.e. x86_64-native-linuxapp-gcc)
```
Build mtcp
```
make all -j
```

### NIC side
['offload_write']



## Run Sample Applications

### Host side
Build lighttpd in [mtcp_accelstorage/apps/lighttpd-1.4.32](mtcp_accelstorage/apps/lighttpd-1.4.32/)
```
cd ./apps/lighttpd-1.4.32/
autoconf
./configure --without-bzip2 CFLAGS="-g -O3" --with-libmtcp=[mtcp path] (i.e. /home/username/IO-TCP/mtcp_accelstorage/mtcp/) --with-libdpdk=[dpdk path] (i.e. /home/username/dpdk/x86_64-native-linuxapp-gcc/) --no-create --no-recursion
make all -j
cd ./src
```
Modify configuration files.
[mtcp_accelstorage/apps/lighttpd-1.4.32/doc/config/m-lighttpd.conf]
```
server.bind=[host ip]
server.event-handler = "mtcp-epoll"
server.network-backend = "mtcp_offload_write"
```
[mtcp_accelstorage/apps/lighttpd-1.4.32/src/mtcp.conf]
```
port=[port name]
```

Run lighttpd
```
./lighttpd -D -f ../doc/config/m-lighttpd.conf -m ./.libs -n 1
```

### NIC side
Set DPDK hugepages with the page size of xxx
./dpdk-20.05/usertools/dpdk-setup.sh

set RTE_SDK and RTE_TARGET
```
export RTE_SDK=[DPDK installation path] (i.e. /root/dpdk-20.05)
export RTE_TARGET=[DPDK target environment] (i.e. arm64-bluefield-linuxapp-gcc)
```
Build the project
```
cd offload_write
make clean
make -j
```
Run 
```
./build/offload_write_separated
```

#### Checklist before performance evaluation
Please check the maximum number of file descriptiors
```
ulimit -n 1000000
```
 
set RTE_SDK and RTE_TARGET
```
export RTE_SDK=[DPDK installation path] (i.e. /home/username/dpdk-20.05)
export RTE_TARGET=[DPDK target environment] (i.e. x86_64-native-linuxapp-gcc)
```

### How to develop IO-TCP application
1. 
2. Use mtcp_offload_open() instead of open()
3. Use mtcp_offload_write()
