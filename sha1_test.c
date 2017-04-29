#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/kallsyms.h>
#include <crypto/public_key.h>
#include <crypto/hash.h>
#include <crypto/sha1_base.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("jstancek");
MODULE_DESCRIPTION("reproduce sha1 avx2 read beyond");

static void *calc_hash(const char *hashname, u8 *d, int len1, int len2)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	int ret = -ENOMEM;
	u8 *digest;
	unsigned int desc_size;
	struct sha1_state *sctx;
	static int digest_size;

	printk("starting test for %s\n", hashname);
	tfm = crypto_alloc_shash(hashname, 0, 0);
	if (IS_ERR(tfm)) {
		printk("failed to alloc %s\n", hashname);
		return (PTR_ERR(tfm) == -ENOENT) ? ERR_PTR(-ENOPKG) : ERR_CAST(tfm);
	}

	desc_size = crypto_shash_descsize(tfm) + sizeof(*desc);
	digest_size = crypto_shash_digestsize(tfm);

	desc = kzalloc(desc_size + digest_size, GFP_KERNEL);
	desc->tfm   = tfm;
	desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	digest = (u8 *) desc + desc_size;

	ret = crypto_shash_init(desc);
	if (ret < 0)
		goto error;

	ret = crypto_shash_update(desc, d, len1);
	if (ret < 0)
		goto error;
	d += len1;

	sctx = shash_desc_ctx(desc);
	printk("count: %llu\n", sctx->count);

	ret = crypto_shash_update(desc, d, len2);
	if (ret < 0)
		goto error;
	d += len2;

error:
	kfree(desc);
	crypto_free_shash(tfm);
	return ERR_PTR(ret);
}

int (*set_memory_np)(unsigned long addr, int numpages);

static int __init sha1test_init(void)
{
	int len, datalen, start_offset;
	u8 *page_after_data;
	u8 *data;
	
	printk("sha_test module loaded\n");
	set_memory_np = (void *) kallsyms_lookup_name("set_memory_np");
	if (!set_memory_np) {
		printk("failed to find set_memory_np\n");
		return -EINVAL;
	}

	if (!kallsyms_lookup_name("sha1_transform_avx2")) {
		printk("failed to find sha1_transform_avx2\n");
		return -EINVAL;
	}

	start_offset = PAGE_SIZE - 148; 
	len = 148 + PAGE_SIZE;
	datalen = PAGE_ALIGN(start_offset + len) + PAGE_SIZE;
	data = kmalloc(datalen, GFP_KERNEL);

	printk("data is at 0x%p, datalen: %d, start_offset: %d, last_byte: 0x%p\n",
		data, datalen, start_offset, data + start_offset + len - 1);
	page_after_data = PTR_ALIGN(data + start_offset + len, PAGE_SIZE);
	printk("page_after_data is at 0x%p\n", page_after_data);

	/* 
 	 * We have 3 pages, hash should use only first 2, we marked
 	 * 3rd one as not present
 	 *  +----------------+------------------+-----------------+
 	 *         PAGE1             PAGE2             PAGE3
 	 *  +----------------+------------------+-----------------+
 	 *  ^ data
 	 *                 ^ start_offset
 	 *                                     ^ last_byte shash should use
 	 *                                       
 	 */
	set_memory_np((unsigned long)page_after_data, 1);

	calc_hash("sha1-generic", data + start_offset, 148, PAGE_SIZE);
	calc_hash("sha1-ni", data + start_offset, 148, PAGE_SIZE);
	calc_hash("sha1-avx", data + start_offset, 148, PAGE_SIZE);
	calc_hash("sha1-avx2", data + start_offset, 148, PAGE_SIZE);
	calc_hash("sha1-ssse3", data + start_offset, 148, PAGE_SIZE);

	/* yes, it leaks memory */
	return 0;
}

static void __exit sha1test_cleanup(void)
{
	printk("sha_test module unloaded\n");
}

module_init(sha1test_init);
module_exit(sha1test_cleanup);
