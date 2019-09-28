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
#include <linux/mutex.h>

#define DEVICE_NAME "crypto"    //Nome do dispositivo, aparece em /dev/crypto 
#define CLASS_NAME "cryptomodule" 


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adriano Munin, Fabio Irokawa, Iago Lourenço, Lucas Coutinho");
MODULE_DESCRIPTION("Modulo de criptografia");
MODULE_VERSION("0.1");

//Modulo

static int majorNumber; //Guarda o numero do dispositivo
static int numAberturas = 0; //Conta quantas vezes o dispositivo foi aberto

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

static char *iv;
static char *key;//Guarda o array de strings recebidos do usuario
static int tamIv=0;
static int tamKey=0; //Para se lembrar do tamanho das strings
static char cryptokey[32];
static char cryptoiv[32];

static DEFINE_MUTEX(crypto_mutex);
static char input[256]={0};
static int tamInput;
static char encrypted[256]={0};
static int tamEncrypted; 
static char decrypted[256]={0};
static int tamDecrypted;
int pos,i;
char op;
char hexa[512]={0};

module_param(iv,charp,0000);
MODULE_PARM_DESC(iv,"Vetor de inicialização");

module_param(key,charp,0000);
MODULE_PARM_DESC(key,"Chave de criptografia");

//Prototipo das funçoes
static int dev_open(struct inode *, struct file *);
static int dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *,char *,size_t,loff_t * );
static ssize_t dev_write(struct file *, const char *,size_t,loff_t *);
static int op_pos(char *);

//Estrutura que define qual função chamar quando 
//o dispositivo é requisitado
static struct file_operations fops = 
{
    .open = dev_open,
    .release = dev_release,
    .read = dev_read,
    .write = dev_write, 
};

//função do nascimento do módulo
static int __init crypto_init(void){
    mutex_init(&crypto_mutex);
    
    /*
    *   Devo pegar os parametros passados(que são strings) e tranferi-los para os char vectors: iv e key
    */
        if(iv!=NULL){
            tamIv=strlen(iv);
        }
        if(key!=NULL){
            tamKey=strlen(key);
        }

        if(tamIv == 0 || tamKey == 0) {
            printk(KERN_ALERT "CRYPTO--> Chave ou iv vazias, encerrando!");
            return -EINVAL;
        }
        printk(KERN_INFO "CRYPTO--> iv len=%d\n",tamIv);
        printk(KERN_INFO "CRYPTO--> key len=%d\n",tamKey);
        
    
    /*Tento alocar um majorNumber para o dispositivo
    *   @param: 1 - se for 0 ele procura um mj livre, mas posso força-lo a usar um que quero
    *           2 - o nome do filho
    *            3 - a struct com as funçoes que podem ser efetuadas  
    *    @return: o mj do dispositivo se deu certo
    *             ou uma flag de erro 
    */
    majorNumber = register_chrdev(0,DEVICE_NAME,&fops);
    if(majorNumber<0){//majorNumbers sao numeros entre 0 e 256
        printk(KERN_ALERT "CRYPTO--> FALHA NO REGISTRO DO DISPOSITIVO\n");
        return majorNumber;
    }
    printk(KERN_INFO "CRYPTO--> Dispositivo criado com o mj=%d\n",majorNumber);

    /*Registra a classe do dispositivo, tenho que entender melhor como a classe funciona
    *    @param: 1 - ponteiro pra esse módulo, no caso usa-se uma constante
    *            2 - nome da classe
    *    @return: flag de erro
    *           struct class  
    *    Há código repetido aqui, pois caso haja falha no registro de
    *    classe e necessario desfazer o que a função acima fez o mesmo vale para o registro de driver
    */
    cryptoClass = class_create(THIS_MODULE,CLASS_NAME);
    if(IS_ERR(cryptoClass)){
        unregister_chrdev(majorNumber,DEVICE_NAME);
        printk(KERN_ALERT "CRYPTO--> FALHA AO REGISTRAR CLASSE\n");
        return PTR_ERR(cryptoClass);
    }
    printk(KERN_INFO "CRYPTO--> Classe registrada\n");

    /*Registra o dispositivo
    *    @param: 1 - ponteiro para classe do dispositivo (criamos ela acima)
    *            2 - caso o device seja dependente de outro passariamos a struct device desse device
    *            3 - cria um objeto device com o nosso mj e mn
    *            4 - nao sei :)
    *            5 - nome do device
    *    @return: a struct device
    *            flag de erro  
    */
    cryptoDev=device_create(cryptoClass,NULL,MKDEV(majorNumber,0),NULL,DEVICE_NAME);
    if(IS_ERR(cryptoDev)){//repeated code :(
        class_destroy(cryptoClass);
        unregister_chrdev(majorNumber,DEVICE_NAME);
        printk(KERN_ALERT "CRYPTO--> FALHA AO REGISTRAR DISPOSITIVO\n");
        return PTR_ERR(cryptoDev);
    }
    printk(KERN_INFO "CRYPTO--> Dispositivo registrado\n");

    return 0;
}

//função assassinadora do módulo :-)
static void __exit crypto_exit(void){
    mutex_destroy(&crypto_mutex);
    device_destroy(cryptoClass,MKDEV(majorNumber,0));
    class_unregister(cryptoClass);
    class_destroy(cryptoClass);
    unregister_chrdev(majorNumber,DEVICE_NAME);
    printk(KERN_INFO "CRYPTO--> Adeus kernel cruel!!\n");
}

static int dev_open(struct inode *inodep,struct file *filep){
    if(!mutex_trylock(&crypto_mutex)){
        printk(KERN_ALERT "CRYPTO--> Requisiçao bloqueada!!\n");
        return -EBUSY;
    }
    
    numAberturas++;
    printk(KERN_INFO "CRYPTO--> Voce ja me abriu %d vezes\n",numAberturas);
    return 0;
}

static int dev_release(struct inode *inodep,struct file *filep){
    mutex_unlock(&crypto_mutex);
    printk(KERN_INFO "CRYPTO--> Modulo dispensado!\n");
    return 0;
}

static ssize_t dev_read(struct file *filep,char *buffer,size_t len,loff_t *offset){
    int erros=0;
    //TODO aqui verificar se e para enviar o decrypted ou o encrypted
    erros=copy_to_user(buffer,encrypted,tamEncrypted);
    //erros=copy_to_user(buffer,decrypted,tamEncrypted);

    if(erros==0){
        printk(KERN_INFO "CRYPTO--> Mensagem com %d caracteres enviada!\n",tamEncrypted);
        return 0;
    }else{
        printk(KERN_ALERT "CRYPTO--> Falha ao enviar mensagem\n");
        return -EFAULT;
    }
}

static ssize_t dev_write(struct file *filep,const char *buffer,size_t len, loff_t *offset){
    strcpy(input,buffer);
    pos = op_pos(input);
    op = input[pos];
    input[pos-1] = '\0';
    tamInput = strlen(input);

    for(i=0;i<tamInput;i++){
        sprintf(hexa+i*2,"%02X",input[i]);
    }
    printk("DEBUG %s\n",hexa);

    if(op == 'c'){
        printk("CRYPTO--> Criptografando..\n");
        //criptografia aqui
    }else if(op == 'd'){
        printk("CRYPTO--> Descriptografando..\n");
        //descriptografia aqui
    }else{
        printk("CRYPTO--> Gerando Hash..\n");
        //hash aqui
    }

    tamEncrypted = strlen(hexa);
    strcpy(encrypted,hexa);
    printk(KERN_INFO "CRYPTO-->  Recebida mensagem com %d caracteres!\n",tamInput);
    return len;
}


static int op_pos(char * str){

int i;
    for (i=0;i<strlen(str);i++){

        if(str[i] == ':'){
            if(str[i+1] == 'c' || str[i+1] == 'd' || str[i+1] == 'h'){
                return i+1;
            }
        }
    }


return 0;
}    

module_init(crypto_init);
module_exit(crypto_exit);