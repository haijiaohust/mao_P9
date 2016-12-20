KVER ?= $(shell uname -r)
KERNELDIR:=/lib/modules/$(KVER)/build
PWD:=$(shell pwd)
CONFIG_F2FS_FS:=m
CONFIG_F2FS_FS_XATTR:=y
CONFIG_F2FS_STAT_FS:=y
CONFIG_F2FS_FS_POSIX_ACL:=y

obj-$(CONFIG_F2FS_FS) += f2fs.o

f2fs-y          := dir.o file.o inode.o namei.o hash.o super.o inline.o
f2fs-y          += checkpoint.o gc.o data.o node.o segment.o recovery.o
f2fs-y          += shrinker.o extent_cache.o f2fs_dump_info.o dedupe.o
f2fs-$(CONFIG_F2FS_STAT_FS) += debug.o
f2fs-$(CONFIG_F2FS_FS_XATTR) += xattr.o
f2fs-$(CONFIG_F2FS_FS_POSIX_ACL) += acl.o
f2fs-$(CONFIG_F2FS_IO_TRACE) += trace.o
f2fs-$(CONFIG_F2FS_FS_ENCRYPTION) += crypto_policy.o crypto.o \
                crypto_key.o crypto_fname.o

default:
	make -C $(KERNELDIR) M=$(PWD) modules
clean:
	rm -rf *.o *.mod.c *.ko *.symvers *.order *.unsigned .*.cmd .tmp_versions f2fs.ko.digest*
