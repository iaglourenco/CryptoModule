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

MODULE_LICENSE("GPL");


static void init_hash(char *textIn, char *digest, int qtdChar)
{
    struct crypto_shash *sha1;
    struct shash_desc *shash;
    int ret;

    sha1 = crypto_alloc_shash("sha1" ,0, 0);
    if (IS_ERR(sha1))
    {
        printk(KERN_ERR  "hash failed erro: nao foi possivel alocar shash");
        return;
    }

    shash = kmalloc(41 ,GFP_KERNEL);
    if (!shash)
    {
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

    kfree(shash);
    crypto_free_shash(sha1);
}

int init_module(void)
{
    char texto[] = {'b', 'a', 'n', 'a', 'n', 'a', '\0'};
    char digest[200];

    printk("Modulo teste Carregado!");

    init_hash(texto, digest, sizeof(texto));

    printk("Texto: %s \n", texto);
    printk("Hash: %s \n", digest);

return 0;
}
void cleanup_module(void)
{
    pr_info("Goodbye world 1.\n");
}
