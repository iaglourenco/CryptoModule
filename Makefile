##Makefile
## Adriano Munin
## Fabio Irokawa
## Iago Lourenço
## Lucas Coutinho

#obj-m += cryptoexample.o
obj-m += ebbchar.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
