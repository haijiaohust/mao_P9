#include <linux/pagemap.h>
#include <crypto/hash.h>
#include <crypto/md5.h>
#include <crypto/sha.h>
#include <crypto/algapi.h>
#include "dedupe.h"
#include <linux/f2fs_fs.h>
#include <linux/vmalloc.h>
#include "f2fs.h"

int f2fs_dedupe_calc_hash(struct page *p, u8 hash[], struct dedupe_info *dedupe_info)
{
	//int i;
	int ret;
	
	struct {
		struct shash_desc desc;
		char ctx[dedupe_info->crypto_shash_descsize];
	} sdesc;
	char *d;

	sdesc.desc.tfm = dedupe_info->tfm;
	sdesc.desc.flags = 0;
	ret = crypto_shash_init(&sdesc.desc);
	if (ret)
		return ret;

	d = kmap(p);
	ret = crypto_shash_digest(&sdesc.desc, d, PAGE_SIZE, hash);
	kunmap(p);

	/*for(i=0;i<4;i++)
	{
		printk("%llx",be64_to_cpu(*(long long*)&hash[i*8]));
	}
	printk("\n");*/

	return ret;
}

#ifdef F2FS_BLOOM_FILTER
int f2fs_dedupe_bloom_filter(u8 hash[], struct dedupe_info *dedupe_info)
{
	int i;
	unsigned int *pos = (unsigned int *)hash;
	for(i=0;i<dedupe_info->bloom_filter_hash_fun_count;i++)
	{
		if(0 == dedupe_info->bloom_filter[*(pos++)&dedupe_info->bloom_filter_mask])
		{
			return 1;
		}
	}
	return 0;
}

void init_f2fs_dedupe_bloom_filter(struct dedupe_info *dedupe_info)
{
	struct dedupe *cur;
	int i;
	for(cur = dedupe_info->dedupe_md; cur < dedupe_info->dedupe_md + dedupe_info->dedupe_block_count * DEDUPE_PER_BLOCK;cur++)
	{
		if(unlikely(cur->ref))
		{
			unsigned int *pos = (unsigned int *)cur->hash;
			for(i=0;i<dedupe_info->bloom_filter_hash_fun_count;i++)
			{
				dedupe_info->bloom_filter[*(pos++)&dedupe_info->bloom_filter_mask]++;
			}
		}
	}
}
#endif


struct dedupe *f2fs_dedupe_search(u8 hash[], struct dedupe_info *dedupe_info)
{
	struct dedupe *c = &dedupe_info->dedupe_md[(*(unsigned int *)hash)%(dedupe_info->dedupe_block_count/64) * DEDUPE_PER_BLOCK*64],*cur;
	c = dedupe_info->dedupe_md;

#ifdef F2FS_BLOOM_FILTER
	if(f2fs_dedupe_bloom_filter(hash, dedupe_info)) return NULL;
#endif

	for(cur=c; cur < dedupe_info->dedupe_md + dedupe_info->dedupe_block_count * DEDUPE_PER_BLOCK; cur++)
	{
		if(unlikely(cur->ref&&!memcmp(hash, cur->hash, dedupe_info->digest_len)))
		{
			dedupe_info->logical_blk_cnt++;
			return cur;
		}
	}
	for(cur = dedupe_info->dedupe_md; cur < c; cur++)
	{
		if(unlikely(cur->ref&&!memcmp(hash, cur->hash, dedupe_info->digest_len)))
		{
			dedupe_info->logical_blk_cnt++;
			return cur;
		}
	}

	return NULL;
}

struct dedupe *f2fs_dedupe_search_by_addr(block_t addr, struct dedupe_info *dedupe_info)
{
	struct dedupe *cur, *c = dedupe_info->last_delete_dedupe;
	
	if(NEW_ADDR == addr) 
		return NULL;

#ifdef F2FS_REVERSE_ADDR
	if(-1 == dedupe_info->reverse_addr[addr])
		return NULL;
	
	cur = &dedupe_info->dedupe_md[dedupe_info->reverse_addr[addr]];
	if(cur->ref)
		return cur;
	else
		return NULL;
#endif

	for(cur=c; cur < dedupe_info->dedupe_md + dedupe_info->dedupe_block_count * DEDUPE_PER_BLOCK; cur++)
	{
		if(unlikely(cur->ref && addr == cur->addr))
			return cur;
	}
	
	for(cur = dedupe_info->dedupe_md; cur < c; cur++)
	{
		if(unlikely(cur->ref && addr == cur->addr))
			return cur;
	}
	return NULL;
}


void set_dedupe_dirty(struct dedupe_info *dedupe_info, struct dedupe *dedupe)
{
	set_bit((dedupe - dedupe_info->dedupe_md)/DEDUPE_PER_BLOCK,  (long unsigned int *)dedupe_info->dedupe_md_dirty_bitmap);
}

int f2fs_dedupe_delete_addr(block_t addr, struct dedupe_info *dedupe_info)
{
	struct dedupe *cur;
	struct f2fs_sb_info *sbi = container_of(dedupe_info, struct f2fs_sb_info, dedupe_info);

	spin_lock(&dedupe_info->lock);
	if(NEW_ADDR == addr)
		return -1;

	cur = f2fs_dedupe_search_by_addr(addr, dedupe_info);
	if(!cur)
	{
		printk("f2fs_dedupe_search_by_addr not found\n");
		return -1;
	}
	else{
		cur->ref--;
		dedupe_info->logical_blk_cnt--;
		dedupe_info->last_delete_dedupe = cur;
		set_dedupe_dirty(dedupe_info, cur);
		if(0 == cur->ref)
		{
#ifdef F2FS_BLOOM_FILTER
			int i;
			unsigned int *pos = (unsigned int *)cur->hash;
			for(i=0;i<dedupe_info->bloom_filter_hash_fun_count;i++)
			{
				dedupe_info->bloom_filter[*(pos++)&dedupe_info->bloom_filter_mask]--;
			}
#endif
			cur->addr = 0;
			dedupe_info->physical_blk_cnt--;
			
#ifdef F2FS_REVERSE_ADDR
			dedupe_info->reverse_addr[addr] = -1;
#endif

			return 0;
		}
		else
		{
			if(unlikely(cur->ref == 4 || cur->ref == 9))
			{
				switch(cur->ref)
				{
					case 4:
						f2fs_dedupe_reli_del_addr(cur->hash, dedupe_info, 1);
						break;
					case 9:
						f2fs_dedupe_reli_del_addr(cur->hash, dedupe_info, 2);
				}
				spin_lock(&sbi->stat_lock);
				sbi->total_valid_block_count--;
				spin_unlock(&sbi->stat_lock);
			}
				
			return cur->ref;
		}
	}
	return -1;
}

int f2fs_dedupe_add(u8 hash[], struct dedupe_info *dedupe_info, block_t addr)
{
	int ret = 0;
	int search_count = 0;
	struct dedupe* cur = &dedupe_info->dedupe_md[(*(unsigned int *)hash)%(dedupe_info->dedupe_block_count/64) * DEDUPE_PER_BLOCK* 64];

	cur = dedupe_info->dedupe_md;
	while(cur->ref)
	{
		if(likely(cur != dedupe_info->dedupe_md + dedupe_info->dedupe_block_count * DEDUPE_PER_BLOCK - 1))
		{
			cur++;
		}
		else
		{
			cur = dedupe_info->dedupe_md;
		}
		search_count++;
		if(search_count>dedupe_info->dedupe_block_count * DEDUPE_PER_BLOCK)
		{
			printk("can not add f2fs dedupe md.\n");
			ret = -1;
			break;
		}
	}
	if(0 == ret)
	{
#ifdef F2FS_BLOOM_FILTER
		unsigned int *pos;
		int i;
#endif
		cur->addr = addr;
		cur->ref = 1;
		memcpy(cur->hash, hash, dedupe_info->digest_len);
#ifdef F2FS_REVERSE_ADDR
		dedupe_info->reverse_addr[addr] = cur - dedupe_info->dedupe_md;
#endif
#ifdef F2FS_BLOOM_FILTER
		pos = (unsigned int *)cur->hash;
		for(i=0;i<dedupe_info->bloom_filter_hash_fun_count;i++)
		{
			dedupe_info->bloom_filter[*(pos++)&dedupe_info->bloom_filter_mask]++;
			//printk("add %d\n", *(pos++)&dedupe_info->bloom_filter_mask);
		}
#endif
		set_dedupe_dirty(dedupe_info, cur);
		dedupe_info->logical_blk_cnt++;
		dedupe_info->physical_blk_cnt++;
	}
	return ret;
}

int f2fs_dedupe_O_log2(unsigned int x)
{
  unsigned char log_2[256] = {
    0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
    6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8
  };
  int l = -1;
  while (x >= 256) { l += 8; x >>= 8; }
  return l + log_2[x];
}

int init_dedupe_info(struct dedupe_info *dedupe_info)
{
	int ret = 0;
	dedupe_info->digest_len = 16;
	spin_lock_init(&dedupe_info->lock);
	INIT_LIST_HEAD(&dedupe_info->queue);
	dedupe_info->dedupe_md = vmalloc(dedupe_info->dedupe_size);
	memset(dedupe_info->dedupe_md, 0, dedupe_info->dedupe_size);
	dedupe_info->dedupe_md_dirty_bitmap = kzalloc(dedupe_info->dedupe_bitmap_size, GFP_KERNEL);
	dedupe_info->dedupe_segment_count = DEDUPE_SEGMENT_COUNT;
	dedupe_info->dedupe_reli = vmalloc(DEDUPE_RELI_NUM * sizeof(dedupe_info->dedupe_reli));
	memset(dedupe_info->dedupe_reli, 0, DEDUPE_RELI_NUM * sizeof(dedupe_info->dedupe_reli));
#ifdef F2FS_BLOOM_FILTER
	dedupe_info->bloom_filter_mask = (1<<(f2fs_dedupe_O_log2(dedupe_info->dedupe_block_count) + 10)) -1;
	dedupe_info->bloom_filter = vmalloc((dedupe_info->bloom_filter_mask + 1) * sizeof(unsigned int));
	memset(dedupe_info->bloom_filter, 0, dedupe_info->bloom_filter_mask * sizeof(unsigned int));
	dedupe_info->bloom_filter_hash_fun_count = 4;
#endif

	dedupe_info->last_delete_dedupe = dedupe_info->dedupe_md;
	dedupe_info->tfm = crypto_alloc_shash("md5", 0, 0);
	dedupe_info->crypto_shash_descsize = crypto_shash_descsize(dedupe_info->tfm);
	return ret;
}

void exit_dedupe_info(struct dedupe_info *dedupe_info)
{
	vfree(dedupe_info->dedupe_md);
	kfree(dedupe_info->dedupe_md_dirty_bitmap);
	kfree(dedupe_info->dedupe_bitmap);
	vfree(dedupe_info->dedupe_reli);
#ifdef F2FS_REVERSE_ADDR
	vfree(dedupe_info->reverse_addr);
#endif
	crypto_free_shash(dedupe_info->tfm);
#ifdef F2FS_BLOOM_FILTER
	vfree(dedupe_info->bloom_filter);
#endif
}

void f2fs_dedupe_reli_add(u8 hash[], struct dedupe_info *dedupe_info, block_t addr, int add_type)
{
	struct dedupe_reli *cur = dedupe_info->dedupe_reli;

	switch(add_type)
	{
		case 1:
			while(cur->addr1 != 0 && cur < dedupe_info->dedupe_reli + DEDUPE_RELI_NUM)
				cur++;
	
			if(likely(cur < dedupe_info->dedupe_reli + DEDUPE_RELI_NUM))
			{
				memcpy(cur->hash, hash, dedupe_info->digest_len);
				cur->addr1 = addr;
				printk("dedupe_reli add1 successed\n");
				return;
			}
			else printk("dedupe_reli is full\n");
			break;
		case 2:
			while(likely(memcmp(cur->hash, hash, dedupe_info->digest_len) && cur < dedupe_info->dedupe_reli + DEDUPE_RELI_NUM))
				cur++;
	
			if(likely(cur < dedupe_info->dedupe_reli + DEDUPE_RELI_NUM))
			{
				cur->addr2 = addr;
				printk("dedupe_reli add2 successed\n");
				return;
			}
			printk("dedupe_reli hash is not found\n");
	}
}

int f2fs_dedupe_reli_del_addr(u8 hash[], struct dedupe_info *dedupe_info, int del_type)
{
	struct dedupe_reli *cur = dedupe_info->dedupe_reli;
	struct f2fs_sb_info *sbi = container_of(dedupe_info, struct f2fs_sb_info, dedupe_info);

	while(memcmp(hash, cur->hash, dedupe_info->digest_len) && cur < dedupe_info->dedupe_reli + DEDUPE_RELI_NUM)
		cur++;

	if(likely(cur < dedupe_info->dedupe_reli + DEDUPE_RELI_NUM))
	{
		//printk("f2fs_dedupe_reli_del_addr\n");
		//printk("%llx %u %u %d\n", be64_to_cpu(*(long long*)&cur->hash), cur->addr1, cur->addr2, del_type);
		dedupe_info->physical_blk_cnt--;
		switch(del_type)
		{
			case 1:
				if(cur->addr2 != 0)
					return -1;
 				else
 				{
 					invalidate_blocks(sbi, cur->addr1);
					cur->addr1 = 0;
					memset(cur->hash, 0, dedupe_info->digest_len);
					printk("dedupe reli del addr1 successed\n");
					return 0;
 				}
			case 2:
				if(cur->addr1 == 0)
					return -1;
				else
				{
					invalidate_blocks(sbi, cur->addr2);
					cur->addr2 = 0;
					printk("dedupe reli del addr2 successed!\n");
					return 0;
				}
		}
	}
	else
	{
		printk("dedupe reli del hash not Found\n");
		return -2;
	}
	return -3;
}

struct dedupe_reli *f2fs_dedupe_reli_search_by_hash(u8 hash[], struct dedupe_info *dedupe_info)
{
	struct dedupe_reli *cur = dedupe_info->dedupe_reli;

	while(memcmp(hash, cur->hash, dedupe_info->digest_len) && cur < dedupe_info->dedupe_reli + DEDUPE_RELI_NUM)
		cur++;

	if(likely(cur < dedupe_info->dedupe_reli + DEDUPE_RELI_NUM))
	{
		printk("dedupe_reli_search_by_hash successed\n");
		return cur;
	}
	printk("dedupe_reli_search_by_hash not found\n");
	return NULL;
}

