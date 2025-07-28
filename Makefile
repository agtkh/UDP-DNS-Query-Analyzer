obj-m := dns_query_analyzer.o

#KH = /usr/src/kernels/5.14.0-503.19.1.el9_5.x86_64
KH = /lib/modules/$(shell uname -r)/build

all:
	make -C ${KH} M=$(PWD) modules

clean:
	make -C ${KH} M=$(PWD) clean

install: all
	sudo insmod dns_query_analyzer.ko

uninstall:
	sudo rmmod dns_query_analyzer

