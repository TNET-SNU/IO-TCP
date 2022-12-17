
# IO-TCP

## Preliminaries

### DPDK
* host-side
	- Download DPDK-20.05 (https://github.com/DPDK/dpdk.git) 
	- mtcp doesn't support later version of DPDK where target specified build is depreciated.
	- Please check that CONFIG_RTE_LIBRTE_MLX5_PMD option has been enabled in dpdk/config/common_base which is disabled by default.
	- Run a script for environment setup
		``` 
		cd ./IO-TCP/mtcp_accelstorage
		./setup_mtcp_dpdk_env.sh [dpdk path] (i.e. 		/home/taehyun/dpdk/)
		```
    - Build DPDK-20.05 with usertools/dpdk-setup.sh
	- In DPDK setup prompt, select a corresponding target. (i.e. x86_64-native-linuxapp-gcc)

* NIC-side
	- Download DPDK-20.05 (https://github.com/DPDK/dpdk.git) 
    - Build DPDK-20.05 with `usertools/dpdk-setup.sh`
    - In DPDK setup prompt, select a corresponding target. (i.e. arm64-bluefield-linuxapp-gcc)

### Mellanox OFED
- Install Mellanox OFED on both the host and the NIC
  - Host
    ```
    cd MLNX_OFED_LINUX-5.3-1.0.0.1-rhel7.6alternate-aarch64/
    ./mlnxofedinstall  --dpdk --upstream-libs --force --add-kernel-support
    dracut -f
    ```
  - NIC
    ```
    ./5-1_install_dependency_for_smartnic.sh
    cd ../
    cd MLNX_OFED_LINUX-5.3-1.0.0.1-rhel7.6alternate-aarch64/
    ./mlnxofedinstall  --dpdk --bluefield --with-nvmf --upstream-libs --force --add-kernel-support
    dracut -f
    ```

### NVMe target offloading
- Need to enable your NIC directly read and write SSDs attached on the host server
- See instructions in [`doc/NVMe_target_offloading.md`](doc/NVMe_target_offloading.md)

### Network setting
- Set your NIC with the separated_host mode
- See details in (https://support.mellanox.com/s/article/BlueField-SmartNIC-Modes)

### Other dependencies
 - Install 
     ```
     ./5-1_install_dependency_for_smartnic.sh
    ``` 
    ```
    yum install  libgmp3-dev
    apt-get install  libgmp3-dev
    ```

## Install

### Host side
- [`host_stack/`](host_stack/): Modified mtcp project.
- Configure 
  ```
  cd host_stack
  autoconf
  ./configure --with-dpdk-lib=[DPDK target path] (i.e. /home/user/dpdk/x86_64-native-linuxapp-gcc/)
  ```
- set RTE_SDK and RTE_TARGET
    ```
    export RTE_SDK=[DPDK installation path] (i.e. /home/username/dpdk-20.05)
    export RTE_TARGET=[DPDK target environment] (i.e. x86_64-native-linuxapp-gcc)
    ```
- Build mtcp
    ```
    make all -j
    ```

### NIC side
- [`nic_stack/`](nic_stack/): NIC stack source code of IO-TCP
  - Set DPDK hugepages with the dpdk script `usertools/dpdk-setup.sh`
  - set RTE_SDK and RTE_TARGET
    ```
    export RTE_SDK=[DPDK installation path] (i.e. /root/dpdk-20.05)
    export RTE_TARGET=[DPDK target environment] (i.e. arm64-bluefield-linuxapp-gcc)
    ```
  - Build the project
    ```
    cd nic_stack
    make -j
    ```

## Run Sample Applications

### lighttpd web server
- Host side
  - Build lighttpd in [host_stack/apps/lighttpd-1.4.32](host_stack/apps/lighttpd-1.4.32/)
      ```
      cd ./apps/lighttpd-1.4.32/
      autoconf
      ./configure --without-bzip2 CFLAGS="-g -O3" --with-libmtcp=[mtcp path] (i.e. /home/username/IO-TCP/mtcp_accelstorage/mtcp/) --with-libdpdk=[dpdk path] (i.e. /home/username/dpdk/x86_64-native-linuxapp-gcc/) --no-create --no-recursion
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
