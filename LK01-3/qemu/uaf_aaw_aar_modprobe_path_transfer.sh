#!/bin/sh

musl-gcc uaf_aaw_aar_modprobe_path.c -o exploit -static

if [ $? -ne 0 ]; then
    echo "compile failed, exiting."
    exit 1
fi

if [ ! -d "root" ]; then
    mkdir root
    cd root
    cpio -idv < ../rootfs.cpio
    cd ..
fi

mv exploit root
cd root; find . -print0 | cpio -o --null --owner=root --format=newc > ../debugfs.cpio
cd ../

qemu-system-x86_64 \
    -m 64M \
    -nographic \
    -kernel bzImage \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on kaslr" \
    -no-reboot \
    -cpu qemu64,+smep,+smap \
    -smp 1 \
    -monitor /dev/null \
    -initrd debugfs.cpio \
    -net nic,model=virtio \
    -s \
    -net user
