obj-m = kernwrite.o

M=$(shell pwd)

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(M) modules

clean:
	rm -rf *.ko *.o *.mod* .*.cmd modules.order Module.symvers .tmp_versions
