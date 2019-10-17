##Makefile
## Adriano Munin
## Fabio Irokawa
## Iago Lourenço
## Lucas Coutinho

#obj-m += cryptoexample.o
#obj-m += ebbchar.o
obj-m += cryptomodule.o
#obj-m += criptoApiDemo.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
new:
	sudo rmmod cryptomodule.ko	
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	sudo insmod cryptomodule.ko key="1234567890abcdef" iv="1234567890abcdef"
	echo Módulo inserido com key="1234567890abcdef" iv="1234567890abcdef". Alterar para testes
