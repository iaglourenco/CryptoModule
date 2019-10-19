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
#include <crypto/internal/hash.h>
#include <linux/vmalloc.h>

#define DEVICE_NAME "crypto"    //Nome do dispositivo, aparece em /dev/crypto 
#define CLASS_NAME "cryptomodule" 
#define BLOCK_SIZE_C 16

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adriano Munin, Fabio Irokawa, Iago Lourenço, Lucas Coutinho");
MODULE_DESCRIPTION("Modulo de criptografia");
MODULE_VERSION("0.1");

static int majorNumber; //Guarda o numero do dispositivo
static int numAberturas = 0; //Conta quantas vezes o dispositivo foi aberto

static struct class* cryptoClass = NULL; //O ponteiro para a struct de classe 
static struct device* cryptoDev = NULL;//O ponteiro para a struct de dispositivo 

/* Struct que guarda o resultado da cripto ou descriptografia */ 
struct tcrypt_result {
    struct completion completion;
    int err;
};
/* Junção com todas as structs utilizadas pelas funçoes de cryptografia */
struct skcipher_def {
    struct scatterlist sg[3];
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
    struct crypto_wait wait;
};
/*
* module_param_array(name, type, num, perm);
* The first param is the parameter's (in this case the array's) name
* The second param is the data type of the elements of the array
* The third argument is a pointer to the variable that will store the number
* of elements of the array initialized by the user at module loading time
* The fourth argument is the permission bits
*/

char *iv;
char *key;//Guarda o array de strings recebidos do usuario
static int tamIv=0;
static int tamKey=0; //Para se lembrar do tamanho das strings
//static char cryptokey[32];
//static char cryptoiv[32];

static DEFINE_MUTEX(crypto_mutex);
static int tamInput;
static char *encrypted;
static int tamEncrypted; 
static char *decrypted;
static int tamDecrypted;
static char hash[41]={0};
static char hashAscii[41]={0};
static int tamHash;
static char *ivLocal;
int pos,i;
char op;
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
static void init_cifra(char *msgInput, char *msgOutput, int opc);
static void ascii2hexa(unsigned char *in, char *out, int len);
static void unpadding(char *string, int len);
static void padding(char *string, int len);
static void init_hash(char *textIn, char *digest, int qtdChar);

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
        if(iv!=NULL) tamIv=strlen(iv);
        
        if(key!=NULL) tamKey=strlen(key);    
        
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
    vfree(encrypted);
    vfree(decrypted);
    return 0;
}

static ssize_t dev_read(struct file *filep,char *buffer,size_t len,loff_t *offset){
    int erros=0;
    //TODO aqui verificar se e para enviar o decrypted ou o encrypted
    
    if(op == 'c'){
        erros=copy_to_user(buffer,encrypted,tamEncrypted);
    }else if(op == 'd'){
        erros=copy_to_user(buffer,decrypted,tamDecrypted);
    }else{
        erros=copy_to_user(buffer,hash,tamHash);
    }
    
    if(erros==0){
        printk(KERN_INFO "CRYPTO--> Mensagem com %d caracteres enviada!\n",tamEncrypted);
        return 0;
    }else{
        printk(KERN_ALERT "CRYPTO--> Falha ao enviar mensagem\n");
        return -EFAULT;
    }
}

static ssize_t dev_write(struct file *filep,const char *buffer,size_t len, loff_t *offset){
    char temp[2];
    char *ascii;
    char *input;    
    char blocoIn[16]={0};
    char blocoCrypto[16]={0};
    int cont = 0, indice;

    tamInput = len - 1;

    if(!(tamInput % 16)){
        input = vmalloc(tamInput + 32);
    }else{
        input = vmalloc(tamInput);    
    }

    if(!input){
        printk(KERN_ERR "kmalloc(input) failed\n");
        return -ENOMEM;
    }

    if(!(tamInput % 16))
        ascii = vmalloc(tamInput/2 + 16);
    else
        ascii = vmalloc(tamInput/2);
    if (!ascii) {
        printk(KERN_ERR  "kmalloc(ascii) failed\n");
        return -ENOMEM;
    }

    ivLocal = vmalloc(16);
    if (!ivLocal) {
        printk(KERN_ERR  "kmalloc(input) failed\n");
        return -ENOMEM;
    }    

    memcpy(ivLocal, iv, 16);
    memcpy(input, buffer+1,tamInput);
  
    op = buffer[0];

    if(op == 'c') {
        padding(input, tamInput); //Caso a opcao seja de criptgrafia, o padding eh feito na entrada.
        tamInput += 32 - (tamInput%32); //Atualiza o tamanho do texto apos o padding    
    } 
   
    //Conversao de hexa para ascii
    for(indice = 0; indice < tamInput; indice+=2){
        temp[0]  = input[indice];
        temp[1]  = input[indice+1];
        sscanf(temp, "%hhx", &ascii[cont]);
        cont++;    
    }

    if(op == 'c'){
        printk("CRYPTO--> Criptografando..\n"); 
        //Aqui entra a criptografia!

        for(indice = 0; indice < cont/16; indice++){//Cont tem a qtd de caracteres ascii, sempre multiplo de 16 (padding)            
            for(i = 0; i < 16; i++){//Copia um bloco para criptografar
                blocoIn[i] = ascii[indice*16 + i];//Indice*16 para deslocar o bloco (Indice tem o num. do bloco)
            }
            init_cifra(blocoIn, blocoCrypto, 1);
            
            for(i = 0; i < 16; i++){//Copia um bloco criptografado 
                ascii[indice*16 +i] = blocoCrypto[i];//Como o bloco atual de ascii ja foi criptografado, ele eh sobrescrito
            }
        }

        encrypted=vmalloc(cont*2);
        if(!encrypted){
            printk(KERN_ERR "kmalloc(encrypted) error");
        }

        ascii2hexa(ascii, encrypted, cont);//ascii tem todos os blocos criptografados
        tamEncrypted = cont*2;
        encrypted[cont*2]='\0';
        printk("DEBUG ASC2HEX %s\n",encrypted);

    }else if(op == 'd'){
        printk("CRYPTO--> Descriptografando..\n"); 
        //descriptografia aqui

        for(indice = 0; indice < cont/16; indice++){//Cont tem a qtd de caracteres ascii, sempre multiplo de 16 (padding)            
            for(i = 0; i < 16; i++){//Copia um bloco para criptografar
                blocoIn[i] = ascii[indice*16 + i];//Indice*16 para deslocar o bloco (Indice tem o num. do bloco)
            }

            init_cifra(blocoIn, blocoCrypto, 2);
            
            for(i = 0; i < 16; i++){//Copia um bloco criptografado 
                ascii[indice*16 +i] = blocoCrypto[i];//Como o bloco atual de ascii ja foi criptografado, ele eh sobrescrito
            }
        }

        decrypted=vmalloc(cont*2);
        if(!decrypted){
            printk(KERN_ERR "kmalloc(encrypted) error");
        }

        ascii2hexa(ascii, decrypted, cont);
        tamDecrypted=strlen(decrypted);
        unpadding(decrypted, tamDecrypted);//Na descriptografia o unpadding eh feito na saida         
        printk("DEBUG HEX2ASC %s\n", decrypted);
    }else{
        printk("CRYPTO--> Gerando Hash..\n");
        //hash aqui
        init_hash(ascii, hashAscii, cont);
        ascii2hexa(hashAscii, hash, 40);
        tamHash = 40;
    }

    printk(KERN_INFO "CRYPTO-->  Recebida mensagem com %d caracteres!\n",tamInput);
    vfree(ascii);
    vfree(input);
    vfree(ivLocal);
    return len;
}

static void ascii2hexa(unsigned char *in, char *out, int len){
    int i = 0;
    while (i < len){        
        sprintf(out+i*2, "%02x", *in++);
        i++;       
    }
}

static void init_cifra(char *msgInput, char *msgOutput, int opc){
        /* local variables */
        struct skcipher_request *req ;
        struct crypto_skcipher *skcipher = NULL;
        struct skcipher_def sk;
        int ret, i;
        char saida[16];
        char entrada[16];

        skcipher = crypto_alloc_skcipher ("cbc(aes)", 0, 0);

        req = skcipher_request_alloc(skcipher, GFP_KERNEL);
        if (req == NULL) {
                printk("failed to load transform for aes");
                goto out;
        }

        ret = crypto_skcipher_setkey(skcipher, key, strlen(key));
        if (ret) {
                printk(KERN_ERR  "setkey() failed\n");
                goto out;
        }

        skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
            crypto_req_done,
            &sk.wait);        

        for(i = 0; i < 16; i++){
            entrada[i] = msgInput[i];
        } 

        sk.tfm = skcipher;
        sk.req = req;

        sg_init_one(&sk.sg[0], entrada, 16);
        sg_init_one(&sk.sg[1], saida, 16);

        if(opc == 1){  
            skcipher_request_set_crypt(req, &sk.sg[0], &sk.sg[1], 16, ivLocal);
            crypto_init_wait(&sk.wait);
            init_completion(&sk.result.completion);
        
            ret = crypto_wait_req(crypto_skcipher_encrypt(sk.req), &sk.wait);
            if (ret) {
                printk(KERN_ERR  "encryption failed erro");
                goto out;
            }
        }else{
            skcipher_request_set_crypt(req, &sk.sg[0], &sk.sg[1], 16, ivLocal);
            crypto_init_wait(&sk.wait);
            init_completion(&sk.result.completion);
        
            ret = crypto_wait_req(crypto_skcipher_decrypt(sk.req), &sk.wait);
            if (ret) {
                printk(KERN_ERR  "encryption failed erro");
                goto out;
            }
        }

    for(i = 0; i < 16; i++){
        msgOutput[i] = saida[i];
    }

    
out:
    if (skcipher)
        crypto_free_skcipher(skcipher);
    if (req)
        skcipher_request_free(req);       
}


static void padding(char *string, int len){ //Padrao utilizado PKCS#7
    int qdtBlocos32, bytesOcupados;
    int i;
    qdtBlocos32 = len/32;   //Obtem a quantidade de blocos completos
    bytesOcupados = len%32; //Obtem a quantidade de bytes usados no ultimo bloco

    if(bytesOcupados == 0){ //Caso a string tenha o tamanho multiplo de 16, preenche um novo blco com o num 0x10 (tamanho do bloco)
        for(i = 0; i < 32; i++){            
            sprintf(string + qdtBlocos32*32 + i*2,"%02x", 16);//Converte 16 decimal para hexa (0x10)
        }
        //string[qdtBlocos32*32 + 32] = '\0';
    }

    else {
        for(i = 0; i < (32 - bytesOcupados); i++){//O ultimo bloco eh preenchido com o valor da qtd de bytes livres
            sprintf(string + qdtBlocos32*32 + i*2 + bytesOcupados,"%02x", (32 - bytesOcupados)/2);
         }
        //string[qdtBlocos32*32 + 32] = '\0';
    }
    
}

static void unpadding(char *string, int len){ //Padrao utilizado PKCS#7
    char temp[3];
    int qtdPadding;//Quantidade de bytes usados no padding
    int numP;//Numero usado para preencher o padding
    int i;

    temp[0]  = string[len-2];//Ultimo numero sempre eh usado para calcular o padding
    temp[1]  = string[len-1];
    temp[2]  = '\0';    
    sscanf(temp, "%x", &qtdPadding);// Converte o num de hexa para decimal

    printk("qtdPadding: %i\n", qtdPadding);

    for(i = 0; i < qtdPadding*2; i += 2){
        temp[0]  = string[len - 2 - i];
        temp[1]  = string[len - 1 - i];
        temp[2]  = '\0';
        sscanf(temp, "%x", &numP);
        if(numP != qtdPadding){//Caso o numero usado para preencher seja diferente da qtd, retorna erro
            printk("Erro de padding\n");
            return; 
        } 
    }
    string[len - qtdPadding*2] = '\0';//Descarta numeros usados no padding
}


static void init_hash(char *textIn, char *digest, int qtdChar){
    struct crypto_shash *sha1;
    struct shash_desc *shash;
    int ret;

    sha1 = crypto_alloc_shash("sha1", 0, 0);
    if (IS_ERR(sha1)){
        printk(KERN_ERR  "hash failed erro: nao foi possivel alocar shash");
        return;
    }

    shash = vmalloc(41);
    if (!shash){
        printk(KERN_ERR  "hash failed erro: %i\n", ENOMEM);
        return;
    }

    shash->tfm = sha1;
    shash->flags = 0;

    ret = crypto_shash_init(shash);
    if (ret){
        printk(KERN_ERR  "hash failed erro: %i\n", ret);
        return;
    }        
        
    ret = crypto_shash_update(shash, textIn, qtdChar);
    if (ret){
        printk(KERN_ERR  "hash failed erro: %i\n", ret);
        return;
    }        
        
    ret = crypto_shash_final(shash, digest);

    if (ret){
        printk(KERN_ERR  "hash failed erro: %i\n", ret);
        return;
    }        

    vfree(shash);
    crypto_free_shash(sha1);
}


module_init(crypto_init);
module_exit(crypto_exit);
