# IO-TCP

## Preliminaries

NVMe target offloading: to enable your NIC directly read and write SSDs attached on the host server



## Install

Host side
['mtcp_acceltrage'](mtcp_accelstorage): Modified mtcp project. We run lighttpd in ['mtcp_accelstorage/apps/lighttpd-1.4.32/'](mtcp_accelstorage/apps/lighttpd-1.4.32/)
NIC side
['offload_write']



## Run Sample Applications

Host side

NIC side
set separated_host mode
https://support.mellanox.com/s/article/BlueField-SmartNIC-Modes

Set huge page
dpdk-20.05/usertools/dpdk-setup.sh

Install offload_write

set appropriate RTE_SDK and RTE_TARGET
export RTE_SDK=/root/dpdk-20.05
export RTE_TARGET=arm64-bluefield-linuxapp-gcc

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
