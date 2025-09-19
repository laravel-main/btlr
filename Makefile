obj-m += btrl.o
CC = gcc -Wall
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
BUILD := $(PWD)/build

all:
	mkdir -p build
	cp $(PWD)/Makefile $(PWD)/build/.
	cp $(PWD)/src/btrl.c $(PWD)/build/.
	make -C $(KDIR) M=$(BUILD) modules

	gcc -o build/btll src/btll.c

clean:
	make -C $(KDIR) M=$(BUILD) clean
	rm -rf build
	rm /bin/btro

install:
	cp $(PWD)/build/btll /bin/btro
