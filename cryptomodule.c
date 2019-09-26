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
#include <linux/kernel.h>   //macros do kernel
#include <linux/fs.h>       // Suporte ao sistema de arquivos linux
#include <linux/uaccess.h>  //Função copy_to_user
#include <linux/crypto.h>   //Funçoes de criptografia

#define DEVICE_NAME "crypto"    //Nome do dispositivo, aparece em /dev/crypto 
#define CLASS_NAME "cryptomodule" 


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adriano Munin, Fabio Irokawa, Iago Lourenço, Lucas Coutinho");
MODULE_DESCRIPTION("Modulo de criptografia");
MODULE_VERSION("0.1");

//Modulo

static int majorNumber; //Guarda o numero do dispositivo
//static char buffer[256] = {0}; //buffer do módulo
//static int tamanho_buffer; //Guarda o tamanho do buffer
static int numAberturas = 0; //Conta quantas vezes o dispositivo foi aberto

//Criptografia
static char *iv[16]; //Guarda o vetor de inicialização
static char *key[16]; //Guarda a chave de criptografia que sera utilizada
static int tamIv=0; //Usada para se lembrar do tamanho do iv
static int tamKey=0; // tamanho da key

static struct class* cryptoClass = NULL; //O ponteiro para a struct de classe 
static struct device* cryptoDev = NULL;//O ponteiro para a struct de dispositivo 

/*
* module_param_array(name, type, num, perm);
* The first param is the parameter's (in this case the array's) name
* The second param is the data type of the elements of the array
* The third argument is a pointer to the variable that will store the number
* of elements of the array initialized by the user at module loading time
* The fourth argument is the permission bits
*/
module_param_array(key,charp,&tamKey,0000);
MODULE_PARM_DESC(key,"Chave de criptografia");

module_param_array(iv,charp,&tamIv,0000);
MODULE_PARM_DESC(iv,"Vetor de inicialização");


//Prototipo das funçoes
static int dev_open(struct inode *, struct file *);
static int dev_release(struct inode *, struct file *);
//static ssize_t dev_read();
//static ssize_t dev_write();

//Estrutura que define qual função chamar quando 
//o dispositivo é requisitado
static struct file_operations fops = 
{
    .open = dev_open,
    .release = dev_release, 
};

//função do nascimento do módulo
static int __init crypto_init(void){

    
    //Tento alocar um majorNumber para o dispositivo
    //@param: 1 - se for 0 ele procura um mj livre, mas posso força-lo a usar um que quero
    //        2 - o nome do filho
    //        3 - a struct com as funçoes que podem ser efetuadas  
    //@return: o mj do dispositivo se deu certo
    //         ou uma flag de erro 
    majorNumber = register_chrdev(0,DEVICE_NAME,&fops);
    if(majorNumber<0){//majorNumbers sao numeros entre 0 e 256
        printk(KERN_ALERT "CRYPTO--> FALHA NO REGISTRO DO DISPOSITIVO\n");
        return majorNumber;
    }
    printk(KERN_INFO "CRYPTO--> Dispositivo criado com o mj=%d\n",majorNumber);

    //Registra a classe do dispositivo, tenho que entender melhor como a classe funciona
    //@param: 1 - ponteiro pra esse módulo, no caso usa-se uma constante
    //        2 - nome da classe
    //@return: flag de erro
    //         struct class  
    //Há código repetido aqui, pois caso haja falha no registro de
    //classe e necessario desfazer o que a função acima fez o mesmo vale para o registro de driver
    cryptoClass = class_create(THIS_MODULE,CLASS_NAME);
    if(IS_ERR(cryptoClass)){
        unregister_chrdev(majorNumber,DEVICE_NAME);
        printk(KERN_ALERT "CRYPTO--> FALHA AO REGISTRAR CLASSE\n");
        return PTR_ERR(cryptoClass);
    }
    printk(KERN_INFO "CRYPTO--> Classe registrada\n");

    //Registra o dispositivo
    //@param: 1 - ponteiro para classe do dispositivo (criamos ela acima)
    //        2 - caso o device seja dependente de outro passariamos a struct device desse device
    //        3 - cria um objeto device com o nosso mj e mn
    //        4 - nao sei :)
    //        5 - nome do device
    //@return: a struct device
    //         flag de erro  
    cryptoDev=device_create(cryptoClass,NULL,MKDEV(majorNumber,0),NULL,DEVICE_NAME);
    if(IS_ERR(cryptoDev)){//repeated code :(
        class_destroy(cryptoClass);
        unregister_chrdev(majorNumber,DEVICE_NAME);
        printk(KERN_ALERT "CRYPTO--> FALHA AO REGISTRAR DISPOSITIVO\n");
        return PTR_ERR(cryptoDev);
    }
    printk(KERN_INFO "CRYPTO--> Dispositivo registrado\n");

    printk("Tamanho IV=%d\n",tamIv);
    printk("Tamanho Key=%d\n",tamKey);
    return 0;
}

//função assassinadora do módulo :-)
static void __exit crypto_exit(void){
    device_destroy(cryptoClass,MKDEV(majorNumber,0));
    class_unregister(cryptoClass);
    class_destroy(cryptoClass);
    unregister_chrdev(majorNumber,DEVICE_NAME);
    printk(KERN_INFO "CRYPTO--> Adeus kernel cruel!!\n");
}

static int dev_open(struct inode *inodep,struct file *filep){
    numAberturas++;
    printk(KERN_INFO "CRYPTO--> Voce ja me abriu %d vezes\n",numAberturas);
    return 0;
}


static int dev_release(struct inode *inodep,struct file *filep){

    printk(KERN_INFO "CRYPTO--> Precisando eh so chamar!!\n");
    return 0;
}

module_init(crypto_init);
module_exit(crypto_exit);