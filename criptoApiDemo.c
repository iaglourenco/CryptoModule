/* 
 * Simple demo explaining usage of the Linux kernel CryptoAPI.
 * By Michal Ludvig <michal@logix.cz>
 *    http://www.logix.cz/michal/
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

#define PFX "cryptoapi-demo: "

MODULE_AUTHOR("Michal Ludvig <michal@logix.cz>");
MODULE_DESCRIPTION("Simple CryptoAPI demo");
MODULE_LICENSE("GPL");


/* Junção com todas as structs utilizadas pelas funçoes de cryptografia */
struct tcrypt_result {
    struct completion completion;
    int err;
};

/* tie all data structures together */
struct skcipher_def {
    struct scatterlist sg[3];
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
    struct crypto_wait wait;
};

/* ====== CryptoAPI ====== */

#define DATA_SIZE       16


static void
hexdump(unsigned char *buf, unsigned int len)
{
        while (len--)
                printk("%02x", *buf++);

        printk("\n");
}

static void cryptoapi_demo(void){

        
        /* config options */
        char *algo = "aes";
        unsigned char key[32];
        char *iv;

        /* local variables */
        struct skcipher_request *req ;
        struct crypto_skcipher *skcipher = NULL;
        struct skcipher_def sk;
        int ret;
        char *input, *encrypted, *decrypted;

        memset(key, 5, sizeof(key)); //Gera uma key preenchida com um

        
        pr_info("Key: %s\n", key);

        
        skcipher = crypto_alloc_skcipher ("cbc(aes)", 0, 0);

        req = skcipher_request_alloc(skcipher, GFP_KERNEL);

        if (req == NULL) {
                printk("failed to load transform for %s \n", algo);
                return;
        }


        ret = crypto_skcipher_setkey(skcipher, key, sizeof(key));

        if (ret) {
                printk(KERN_ERR PFX "setkey() failed\n");
                goto out;
        }

        input = kmalloc(16, GFP_KERNEL);
        if (!input) {
                printk(KERN_ERR PFX "kmalloc(input) failed\n");
                goto out;
        }
        
        iv = kmalloc(16, GFP_KERNEL);
        if (!iv) {
                printk(KERN_ERR PFX "kmalloc(input) failed\n");
                goto out;
        }


        encrypted = kmalloc(16, GFP_KERNEL);
        if (!encrypted) {
                printk(KERN_ERR PFX "kmalloc(encrypted) failed\n");
                kfree(input);
                goto out;
        }

        decrypted = kmalloc(16, GFP_KERNEL);
        if (!decrypted) {
                printk(KERN_ERR PFX "kmalloc(decrypted) failed\n");
                kfree(encrypted);
                kfree(input);
                goto out;
        }

        memset(iv, 2, DATA_SIZE);
        memset(input, 97, DATA_SIZE);
        
        sprintf(input,"%s","Lucas Rodrigues ");
        

        pr_info("input: %s\n", input);

        sk.tfm = skcipher;
        sk.req = req;

        sg_init_one(&sk.sg[0], input, 16);
        sg_init_one(&sk.sg[1], encrypted, 16);
        sg_init_one(&sk.sg[2], decrypted, 16);
        

        skcipher_request_set_crypt(req, &sk.sg[0], &sk.sg[1], 16, iv);
        crypto_init_wait(&sk.wait);
        init_completion(&sk.result.completion);

        ret = crypto_skcipher_encrypt(req);
        if (ret) {
                printk(KERN_ERR PFX "encryption failed erro");
                goto out_kfree;
        }
           
        memset(iv, 2, DATA_SIZE);        

        skcipher_request_set_crypt(req, &sk.sg[1], &sk.sg[2], 16, iv);
        crypto_init_wait(&sk.wait);
        init_completion(&sk.result.completion);

        ret = crypto_skcipher_decrypt(req);
        if (ret) {
                printk(KERN_ERR PFX "encryption failed erro");
                goto out_kfree;
        }

        printk(KERN_ERR PFX "Input: "); hexdump(input, DATA_SIZE);
        printk(KERN_ERR PFX "Encrypted: "); hexdump(encrypted, DATA_SIZE);
        printk(KERN_ERR PFX "Decrypted: "); hexdump(decrypted, DATA_SIZE);

        if (memcmp(input, decrypted, DATA_SIZE) != 0)
                printk(KERN_ERR PFX "FAIL: input buffer != decrypted buffer\n");
        else
                printk(KERN_ERR PFX "PASS: encryption/decryption verified\n");

out_kfree:
        kfree(decrypted);
        kfree(encrypted);
        kfree(input);

out:
    if (skcipher)
        crypto_free_skcipher(skcipher);
    if (req)
        skcipher_request_free(req);
}

/* ====== Module init/exit ====== */

static int __init
init_cryptoapi_demo(void)
{
        cryptoapi_demo();

        return 0;
}

static void __exit
exit_cryptoapi_demo(void)
{
}

module_init(init_cryptoapi_demo);
module_exit(exit_cryptoapi_demo);
