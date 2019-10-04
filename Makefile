##Makefile
## Adriano Munin
## Fabio Irokawa
## Iago Lourenço
## Lucas Coutinho

#obj-m += cryptoexample.o
#obj-m += ebbchar.o
obj-m += cryptomodule.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
new:
	sudo rmmod cryptomodule.ko	
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	sudo insmod cryptomodule.ko key="abc" iv="abc"
	echo Módulo inserido com key="abc" iv="abc". Alterar para testes
