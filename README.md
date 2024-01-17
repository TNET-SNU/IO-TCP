
# IO-TCP

## Preliminaries

### DPDK 
- Install DPDK on both the host and the NIC (https://github.com/DPDK/dpdk.git)
  - IO-TCP links the DPDK library using pkg-config
  - Host
    - Please check that CONFIG_RTE_LIBRTE_MLX5_PMD option has been enabled in dpdk/config/common_base which is disabled by default.
  - NIC
    - OS installation on NIC using bfb images may already have DPDK installed, which cannot be reinstalled.
### Mellanox OFED
- Install Mellanox OFED on both the host and the NIC
  - Host
    ```
    cd MLNX_OFED_LINUX-[version-architecture]/
    ./mlnxofedinstall  --upstream-libs --with-nvmf --with-rshim
    # do not user --dpdk option. It may change the nvme driver and break nvme target offloading. 
    dracut -f
    ```
  - NIC
    ```
    cd MLNX_OFED_LINUX-[version-architecture]/
    ./mlnxofedinstall  --dpdk --bluefield --with-nvmf --upstream-libs --force --add-kernel-support
    dracut -f
    ```
    - OS installation on NIC using bfb images may already have MLNX OFED driver installed, which cannot be reinstalled.

### NVMe target offloading
- Need to enable your NIC directly read and write SSDs attached on the host server
- See instructions in [`doc/NVMe_target_offloading.md`](doc/NVMe_target_offloading.md)

### Network setting
- Set your NIC with the separated_host mode
- See details in (https://support.mellanox.com/s/article/BlueField-SmartNIC-Modes)

## Install

### Host side
  - [`host_stack/`](host_stack/): Modified mtcp project.
  - Configure 
    ```
    cd host_stack
    autoreconf -ivf
    ./configure --with-dpdk-lib
    ```
- Edit hard-coded MAC address
  - In host_stack/mtcp/src/ip_out.c:195~200, Hard-coded SmartNIC MAC address needs to be changed.
- Build mtcp
    ```
    make all -j
    ```
- Build & run your application

### NIC side
- [`nic_stack/`](nic_stack/): NIC stack source code of IO-TCP
  - Set DPDK hugepages. If necessary, set the page size to 1GB instead of the default of 2MB.
  - Build IO-TCP nic stack
    ```
    cd nic_stack
    make -j
    ```
  - Run IO-TCP nic stack
    ```
    ./build/offload_write_separated
    ```

## Run Sample Applications

### lighttpd web server
- Host side
  - Build lighttpd in [host_stack/apps/lighttpd-1.4.32](host_stack/apps/lighttpd-1.4.32/)
      ```
      cd ./apps/lighttpd-1.4.32/
      autoconf
      ./configure --without-bzip2 CFLAGS="-g -O3" --with-libmtcp=[mtcp path] (i.e. /home/username/IO-TCP/host_stack/mtcp/) --with-libdpdk --no-create --no-recursion
      make all -j
      cd ./src
      ```
  - Modify configuration files. 
    - `host_stack/apps/lighttpd-1.4.32/doc/config/m-lighttpd.conf`
      ```
      server.bind=[host ip]
      server.event-handler = "mtcp-epoll"
      server.network-backend = "mtcp_offload_write"
      ```
     - `mtcp_accelstorage/apps/lighttpd-1.4.32/src/mtcp.conf`
       ```
       port=[port name]
       ```
  - Run lighttpd
      ```
      ./lighttpd -D -f ../doc/config/m-lighttpd.conf -m ./.libs -n 1
      ```
- NIC side
  - Run IO-TCP nic stack
    ```
    ./build/offload_write_separated
    ```

### Checklist before performance evaluation
- Please check the maximum number of file descriptiors
