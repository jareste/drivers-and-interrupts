obj-m := srcs/keyboard_logger.o

all: .gitignore
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	sudo insmod srcs/keyboard_logger.ko

uninstall:
	sudo rmmod keyboard_logger


.gitignore:
	@if [ ! -f .gitignore ]; then \
		echo ".gitignore not found, creating it..."; \
		echo ".gitignore" >> .gitignore; \
		echo "*" >> .gitignore; \
		echo "!srcs/" >> .gitignore; \
		echo "Makefile" >> .gitignore; \
		echo "srcs/*" >> .gitignore; \
		echo "!srcs/keyboard_logger.c" >> .gitignore; \
		echo "!srcs/show_logs.py" >> .gitignore; \
		echo "!.git" >> .gitignore; \
		echo ".gitignore created and updated with entries."; \
	else \
		echo ".gitignore already exists."; \
	fi

show:
	sudo tail -f /dev/jareste_keylogger
