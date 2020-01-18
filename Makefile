obj-m += sandfs.o
sandfs-objs = dentry.o file.o inode.o main.o super.o lookup.o mmap.o bpf.o
KERNELDIR := /lib/modules/`uname -r`/build
PWD := $(shell pwd)
default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)  modules 
clean:
	rm -fr *.mod *.o *.cmd *.mod.c *.unsigned  .*.cmd .tmp_versions/ Module.symvers modules.order *.ko
