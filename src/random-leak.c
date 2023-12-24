/* SPDX-License-Identifier: GPL-2.0 */
/*
 * random-leak - leak random kernel memory via kallsyms
 * Copyright (c) 2023 Amy Parker <amy@amyip.net>
 */

/*
 * Known limitations:
 *
 * - Only pulls data from symbols in `kallsyms`. If you want
 *   truly random kernel data, you'd likely need to perform
 *   operations with the memory mapper that would be incredibly
 *   unsafe and potentially architecture-dependent.
 * - May occasionally cause a BUG/OOPS trigger on a #PF/equiv.
 *   This happens if a part of kernel memory gets unloaded
 *   before it can be read from. If this happens, you can keep
 *   using things like normal - but DON'T UNLOAD THE MODULE.
 *   Unloading the module after a failure will prevent you from
 *   reloading it and will force you to hard-reboot when you
 *   want to shut down. Shutting down without unloading works fine.
 * - Functionality depends on kprobes working and being unrestricted,
 *   as well as kallsyms and other symbols not having been uncompiled
 *   from the kernel. The latter will not show at compile time.
 */

#define pr_fmt(fmt) "%s: " fmt, KBUILD_MODNAME

#include <linux/init.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/kstrtox.h>
#include <linux/sprintf.h>
#include <linux/kprobes.h>
#include <linux/err.h>
#include <linux/minmax.h>
#include <crypto/rng.h>
#include <asm/page.h>

// Only here to please analyzers, not needed for compilation
#ifndef random_leak
#define random_leak "random-leak"
#endif

// average number of kernel symbols ~ 2^18
// quicker than counting the ~2^18 entries 
const size_t RAND_DET = (1UL << 18);

static size_t BYTES_TO_FETCH = 16;
typedef int (*_kallsyms_oes_t)(int (*fn)(void *, const char *, unsigned long), void *);
static _kallsyms_oes_t _kallsyms_on_each_symbol;
static struct crypto_rng *rng;

static struct proc_dir_entry *proc_ent;

struct data_kallsyms_it {
	char __user *buf;
	size_t count_rem;
	size_t bytes_cache;
};

union Packed32 {
	u32 pack;
	u8 bytes[4];
};

static int iterate_kallsyms(void *data,
                            const char *namebuf,
                            unsigned long symaddr) {
	// we want any given sym to have a 1/(8*n/k) chance of being selected
	// n = number of syms, k = number of bytes to pull
	// 8 is the expected value of bytes to pull from any given symbol (mod 16)
	union Packed32 buf;
	crypto_rng_get_bytes(rng, buf.bytes, 4);
	// endianness of read doesn't matter
	if (buf.pack % ((RAND_DET / BYTES_TO_FETCH) << 3) != 0)
		return 0;
	struct data_kallsyms_it *dat = (struct data_kallsyms_it *) data;
	crypto_rng_get_bytes(rng, buf.bytes, 1);
 	// bytes to pull: min3(count_rem, rand, PAGE_SIZE - (symaddr % PAGE_SIZE)) % 16
	size_t rem_in_page = (size_t)(PAGE_SIZE - (symaddr % PAGE_SIZE));
	size_t bytes = min3(dat->count_rem, (size_t) buf.bytes[0], rem_in_page) % 16;
	// get location to start reading from
	crypto_rng_get_bytes(rng, buf.bytes, 4);
	char *const loc = (char *) symaddr + ((size_t) buf.pack % (rem_in_page - bytes));
	for (size_t i = 0; i < bytes; ++i) {
		const char b = loc[i];
		if (b != 0) {
			dat->buf[dat->bytes_cache - dat->count_rem] = b;
			dat->count_rem -= 1;
		}
	}
	return dat->count_rem == 0 ? 1 : 0;  
}

static ssize_t proc_read(struct file *file,
                         char __user *buf,
                         size_t count,
                         loff_t *offset) {
	size_t bytes_cache = READ_ONCE(BYTES_TO_FETCH);
	// will try and keep reading on forever
	// only accept reads starting at beginning
	if (*offset > 0)
		return 0;
	if (count < bytes_cache + 1)
		return -EINVAL;
	char *nbuf = kzalloc(bytes_cache + 1, GFP_KERNEL);
	nbuf[bytes_cache] = 0;
	struct data_kallsyms_it dat = {
	    .buf = nbuf,
	    .count_rem = bytes_cache,
		.bytes_cache = bytes_cache
	};
	while (dat.count_rem > 0)
		_kallsyms_on_each_symbol(iterate_kallsyms, &dat);
	size_t len = bytes_cache + 1;
	*offset = len;
	if (copy_to_user(buf, nbuf, len)) {
		kfree_sensitive(nbuf);
        return -EFAULT;
	}
	kfree_sensitive(nbuf);
  	return bytes_cache + 1;
}

// NOTE: not working yet
static ssize_t proc_write(struct file *file,
                          const char __user *buf,
                          size_t count,
                          loff_t *offset) {
	u32 new_bytes_val;
	char nbuf[11];
	if (copy_from_user(nbuf, buf, min(count, 10UL)))
		return -EFAULT;
	nbuf[10] = 0;
	u32 ret = kstrtou32(nbuf, 10, &new_bytes_val);
	if (ret != 0)
		return ret;
	// avoid DBZ
	if (new_bytes_val == 0)
		return -EINVAL;
	WRITE_ONCE(BYTES_TO_FETCH, new_bytes_val);
	return count;
}

const static struct proc_ops fops = {
	.proc_read = proc_read,
	.proc_write = proc_write
};

static struct kprobe kp = {
	.symbol_name = "kallsyms_on_each_symbol"
};

static void __exit custom_exit(void) {
  	proc_remove(proc_ent);
  	_kallsyms_on_each_symbol = (_kallsyms_oes_t) NULL;
  	if (rng != NULL) {
		crypto_free_rng(rng);
		rng = (struct crypto_rng *) NULL;
  	}
}

static int __init custom_init(void) {
	rng = crypto_alloc_rng("drbg_nopr_sha256", 0, 0);
	if (IS_ERR(rng) || rng == NULL) {
		return PTR_ERR(rng);
	}
	crypto_rng_alg(rng)->seed(rng, NULL, 0);
	register_kprobe(&kp);
	if (kp.addr == 0) {
		unregister_kprobe(&kp);
		proc_remove(proc_ent);
		return -ENOSYS;
	}
	_kallsyms_on_each_symbol = (_kallsyms_oes_t) kp.addr;
	unregister_kprobe(&kp);
	proc_ent = proc_create("random-leak", 0600, NULL, &fops);
	return 0;
}

module_init(custom_init);
module_exit(custom_exit);

MODULE_AUTHOR("Amy Parker");
MODULE_DESCRIPTION("Leak random parts of kernel memory");
MODULE_LICENSE("GPL");