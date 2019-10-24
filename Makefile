##Makefile
## Adriano Munin
## Fabio Irokawa
## Iago Lourenço
## Lucas Coutinho

obj-m += cryptomodule.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc cryptoteste.c -o crypto
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
def:
	sudo insmod cryptomodule.ko key="1234567890abcdef" iv="1234567890abcdef"
new:
	sudo rmmod cryptomodule.ko	
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	sudo insmod cryptomodule.ko key="1234567890abcdef" iv="1234567890abcdef"
crypto: cryptoteste.c
	gcc cryptoteste.c -o crypto
