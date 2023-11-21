obj-m += DSMmodule.o

KDIR := /lib/modules/$(shell uname -r)/build
hello:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean