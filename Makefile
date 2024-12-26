obj-m := srcs/keyboard_logger.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	sudo insmod srcs/keyboard_logger.ko

uninstall:
	sudo rmmod srcs/keyboard_logger
