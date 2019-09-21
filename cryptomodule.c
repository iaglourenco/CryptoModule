/**
 * @arquivo   cryptomodule.c
 * @autores Adriano Munin, Fabio Irokawa, Iago Lourenço e Lucas Coutinho
 * @data   Setembro 2019
 * @versão 0.1
 * @descrição Projeto de SOB para a crição de um módulo de kernel linux.
 * @veja http://github.com/iaglourenco/CryptoModule para saber mais.
 */

#include <linux/init.h>     //Funçoes __init, __exit 
#include <linux/module.h>   //Necessario pra qualquer modulo de kernel
#include <linux/device.h>   // Suporte para modulos de dispositivos
#include <linux/fs.h>       // Suporte ao sistema de arquivos linux
#include <linux/uaccess.h>  //Função copy_to_user
#include <linux/crypto.h>   //Funçoes de criptografia

#define DEVICE_NAME "crypto"    //Nome do dispositivo, aparece em /dev/crypto 
#define CLASS_NAME "cryptomodule" 


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adriano Munin, Fabio Irokawa, Iago Lourenço, Lucas Coutinho");
MODULE_DESCRIPTION("Modulo de criptografia");
MODULE_VERSION("0.1");




