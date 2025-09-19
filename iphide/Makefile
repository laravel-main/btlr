obj-m += iphide.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

install:
	sudo insmod iphide.ko

uninstall:
	sudo rmmod iphide

.PHONY: all clean install uninstall
