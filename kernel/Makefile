obj-m += safe.o
safe-objs := hook.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(RM) -rf .*.cmd *.mod.c *.o *.ko .tmp*
