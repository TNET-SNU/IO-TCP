# run at SmartNIC

# enable internet
ifdown eth0; ifup eth0

# dependency
yum groups mark install "Development Tools"
yum groups mark convert "Development Tools"
yum -y install rpm-build
yum -y group install "Development Tools"
yum -y install kernel-devel-`uname -r`
yum -y install valgrind-devel libnl3-devel python-devel
yum -y install tcl tk 
yum -y install unbound

# remove pre-installed kernel modules
mkdir /boot/tmp
cd /boot/tmp
gunzip  <  ../initramfs-4*64.img  | cpio -i
rm -f lib/modules/4*/updates/mlx5_core.ko
rm -f lib/modules/4*/updates/tmfifo*.ko
cp ../initramfs-4*64.img ../initramfs-4.11.0-22.el7a.aarch64.img-bak
find | cpio -H newc -o | gzip -9 > ../initramfs-4*64.img
rpm -e mlx5_core
depmod -a
