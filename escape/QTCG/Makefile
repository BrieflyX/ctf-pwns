obj-m = pwn.o
all: build

build:
	make -C ./linux-5.0.5 M=$(PWD) modules
clean:
	make -C ./linux-5.0.5 M=$(PWD) clean
