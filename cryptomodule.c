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
#include <crypto/skcipher.h>   //Funçoes de criptografia
#include <linux/mutex.h>
#include <linux/scatterlist.h>

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

/* Struct que guarda o resultado da cripto ou descriptografia */ 
struct tcrypt_result{
    struct completion completion;
    int err;
};
/* Junção com todas as structs utilizadas pelas funçoes de cryptografia */
static struct skcipher_def{
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
};
/*
* module_param_array(name, type, num, perm);
* The first param is the parameter's (in this case the array's) name
* The second param is the data type of the elements of the array
* The third argument is a pointer to the variable that will store the number
* of elements of the array initialized by the user at module loading time
* The fourth argument is the permission bits
*/

#define TAM_IV 16
#define TAM_KEY 16

static char *iv;
static char *key;//Guarda o array de strings recebidos do usuario
static int tamIv=0;
static int tamKey=0; //Para se lembrar do tamanho das strings

static DEFINE_MUTEX(crypto_mutex);

static char input;
static char encrypted;
static char decrypted;
static char hash;

static struct skcipher_def sk;
static struct crypto_skcipher *skcipher = NULL;
static struct skcipher_request *req = NULL;
int pos,i;
char op;
char hexa[512]={0};
int inteiros[256];
char buf;

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
static unsigned int perform_crypto_decrypto(struct skcipher_def*,int);
static int init_cifra(char*,char*,unsigned char*,int );

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
    int ret=0;
    if(iv!=NULL) tamIv=strlen(iv);
    if(key!=NULL) tamKey=strlen(key);    
        

    if(tamIv < TAM_IV || tamKey < TAM_KEY) {
        printk(KERN_ALERT "CRYPTO--> Chave ou iv invalidas, encerrando!");
        return -EINVAL;
    }
    printk(KERN_INFO "CRYPTO--> IV lenght=%d\n",tamIv);
    printk(KERN_INFO "CRYPTO--> KEY lenght=%d\n",tamKey);
        
    
    /*Tento alocar um majorNumber para o dispositivo*/
    majorNumber = register_chrdev(0,DEVICE_NAME,&fops);
    if(majorNumber<0){//majorNumbers sao numeros entre 0 e 256
        printk(KERN_ALERT "CRYPTO--> FALHA NO REGISTRO DO DISPOSITIVO\n");
        ret = majorNumber;
        goto free;
    }
    printk(KERN_INFO "CRYPTO--> Dispositivo criado com o mj=%d\n",majorNumber);

    /*Registra a classe do dispositivo    */
    cryptoClass = class_create(THIS_MODULE,CLASS_NAME);
    if(IS_ERR(cryptoClass)){
        printk(KERN_ALERT "CRYPTO--> FALHA AO REGISTRAR CLASSE\n");
        ret = PTR_ERR(cryptoClass);
        goto free;
    }
    printk(KERN_INFO "CRYPTO--> Classe registrada\n");

    /*Registra o dispositivo*/
    cryptoDev=device_create(cryptoClass,NULL,MKDEV(majorNumber,0),NULL,DEVICE_NAME);
    if(IS_ERR(cryptoDev)){//repeated code :(
       
        printk(KERN_ALERT "CRYPTO--> FALHA AO REGISTRAR DISPOSITIVO\n");
        ret = PTR_ERR(cryptoDev);
        goto free;
    }
    printk(KERN_INFO "CRYPTO--> Dispositivo registrado\n");

    printk(KERN_INFO "Inicilizando cryptoAPI\n");
    init_cifra(iv,key,tamKey);

    goto ret;


free:
    unregister_chrdev(majorNumber,DEVICE_NAME);
    if(cryptoClass)
        class_destroy(cryptoClass);
ret:
    return ret;
}

//função assassinadora do módulo :-)
static void __exit crypto_exit(void){
    mutex_destroy(&crypto_mutex);
    device_destroy(cryptoClass,MKDEV(majorNumber,0));
    class_unregister(cryptoClass);
    class_destroy(cryptoClass);
    unregister_chrdev(majorNumber,DEVICE_NAME);
    crypto_free_skcipher(skcipher);
    skcipher_request_free(req);
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
  
    if(op == 'c'){
        erros=copy_to_user(buffer,encrypted,sizeof(encrypted));
    }else if(op == 'd'){
        erros=copy_to_user(buffer,decrypted,sizeof(decrypted));
    }else{
        erros=copy_to_user(buffer,hash,sizeof(hash));
    }
    
    if(erros==0){
        printk(KERN_INFO "CRYPTO--> Mensagem enviada! OP=%c\n",op);
        return 0;
    }else{
        printk(KERN_ALERT "CRYPTO--> Falha ao enviar mensagem\n");
        return -EFAULT;
    }
}

static ssize_t dev_write(struct file *filep,const char *buffer,size_t len, loff_t *offset){
    char temp[3]; //variaveis temporarias de conversao
    int cont = 0;

    strcpy(input, buffer);
    pos = op_pos(input);//encontro o tipo de operacao requerida
    op = input[pos];
    input[pos-1] = '\0';
    
    kmalloc(sizeof(input),GFP_KERNEL);

    if(op == 'c'){
        printk("CRYPTO--> Criptografando..\n");
        
        //Conversao de hexa para inteiro
        for(i = 0; i < sizeof(input); i+=2){
            temp[0]  = input[i];
            temp[1]  = input[i+1];
            temp[2]  = '\0'; 
            sscanf(temp, "%x", &inteiros[cont]);
            cont++;    
        }

        sg_init_one(&sk.sg,inteiros,sizeof(inteiros));
        skcipher_request_set_crypt(req,&sk.sg,&sk.sg,16,iv);
        init_completion(&sk.result.completion);
        perform_crypto_decrypto(sk,1);
        sg_copy_to_buffer(&sk.sg, 8, encrypted, 8);

        
        //Aqui entra a criptografia, criptografando o vetor inteiros
   
        //Conversao de inteiro para hexa
        for(i = 0; i < cont; i++){                  
            sprintf(encrypted+i*2,"%x", inteiros[i]);
        }        
        
    }else if(op == 'd'){
        printk("CRYPTO--> Descriptografando..\n");
        
        //Conversao de hexa para inteiro
        for(i = 0; i < sizeof(input); i+=2){
            temp[0]  = input[i];
            temp[1]  = input[i+1];
            temp[2]  = '\0'; 
            sscanf(temp, "%x", &inteiros[cont]);
            cont++;    
        }
        
        //Aqui entra a descriptografia, descriptografando o vetor inteiros
        sg_init_one(&sk.sg,inteiros,sizeof(inteiros));
        skcipher_request_set_crypt(req,&sk.sg,&sk.sg,sizeof(inteiros),iv);
        init_completion(&sk.result.completion);
        perform_crypto_decrypto(sk,0);


        //Conversao de inteiro para hexa
        for(i = 0; i < cont; i++){                  
            sprintf(decrypted+i/2,"%x", inteiros[i]);
        }

    }else{
        printk("CRYPTO--> Gerando Hash..\n");
        //hash aqui
        tamHash=strlen("Nao implementado ainda :(");
        strcpy(hash,"Nao implementado ainda :(");
    }

    printk(KERN_INFO "CRYPTO-->  Recebida mensagem com %d caracteres!\n",sizeof(input));
    return len;
}

//Faz a criptografia ou descriptografia com os dados preenchidos em skcipher
static unsigned int perform_crypto_decrypto(struct skcipher_def *sk,int action){
    
    int rc = 0;

    if(action == 1 ){
        rc=crypto_skcipher_encrypt(sk->req);
    }else{
        rc=crypto_skcipher_decrypt(sk->req);
    }
    
    switch(rc){
        case 0:
            break;
            case -EINPROGRESS:
            case -EBUSY:
            rc = wait_for_completion_interruptible(&sk->result.completion);
            if(!rc && !sk->result.err){
                reinit_completion(&sk->result.completion);
                break;
            }
        default:
            printk(KERN_ALERT "CRYPTO--> crypto retornou rc=%d err=%d\n",rc,sk->result.err);
            break;    
    }
    init_completion(&sk->result.completion);
    return rc;
}

static int init_cifra(char *iv,unsigned char *key,int key_len){
 
    int ret = -EFAULT;

    skcipher = crypto_alloc_skcipher("cbc-aes-aesni",0,0);
    if(IS_ERR(skcipher)){
        printk(KERN_ALERT "CRYPTO--> Falha ao alocar skcipher\n");
        return PTR_ERR(skcipher);
    }

    req = skcipher_request_alloc(skcipher,GFP_KERNEL);
    if(!req){
        printk(KERN_ALERT "CRYPTO--> Falha ao alocar skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    if(crypto_skcipher_setkey(skcipher,key,key_len)){
        printk(KERN_ALERT "CRYPTO--> Falha ao definir chave\n");
        ret = -EAGAIN;
        goto out;
    }

    sk.tfm = skcipher;
    sk.req = req;


     
 

    
    return ret;
    
out:
    if(skcipher)
        crypto_free_skcipher(skcipher);
    if(req)
        skcipher_request_free(req);
    return ret;

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
