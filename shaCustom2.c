#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <crypto/hash.h> 
#include <linux/device.h> 
#include <linux/fs.h>

#define blocksize 64
#define digestsize 20
//ambos tamanhos mencionados no proc/crypto
//tamanhos para o sha1

MODULE_AUTHOR("Michal Ludvig <michal@logix.cz>");
MODULE_DESCRIPTION("Simple CryptoAPI demo");
MODULE_LICENSE("GPL");

struct hash_def{
        struct scatterlist sg;
        struct crypto_shash *sha;
};

struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

static int hash_test(void)
{
        struct crypto_shash *sha = NULL;
        struct shash_desc *shash;
        int size, ret;
        static char input[] = "123123";
        static char output[40];

        sha = crypto_alloc_shash("sha1",0,0);
        if (IS_ERR(sha)) {
                printk("can't alloc sha\n");
                return 0;
        }

        size = sizeof(struct shash_desc) + crypto_shash_descsize(sha);
        shash = kmalloc(size, GFP_KERNEL);
        if (!shash)
                return 0;
        shash->tfm = sha;
        shash->flags = 0x0;

        ret = crypto_shash_digest(shash, input, 6, output);
        kfree(shash);
        crypto_free_shash(sha); //libera sha

        printk("Input: %s",input);
        printk("Output: %d",*output);

        //kfree(input);
        //kfree(output);

        return 1;    
}

static int __init hash_start(void)
{
        hash_test();
        return 0;
}
static void __exit hash_finish(void)
{
        pr_info("Goodbye world 1.\n");
}

module_init(hash_start);
module_exit(hash_finish);