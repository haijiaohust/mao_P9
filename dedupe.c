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

int dedupe_bloom_filter(u8 hash[], struct dedupe_info* dedupe_info)
{
	int i;
	unsigned int *pos = (unsigned int*)hash;
	for(i = 0; i < dedupe_info->bloom_filter_hash_fun_count; i++){
		if(!test_bit((*pos)&dedupe_info->bloom_filter_mask, (long unsigned int*)dedupe_info->bloom_filter))
			return 1;
		pos++;
	}
	return 0;
}
int dedupe_bloom_filter_add(u8 hash[], struct dedupe_info* dedupe_info)
{
	int i;
	unsigned int *pos = (unsigned int*)hash;
	if(dedupe_bloom_filter(hash, dedupe_info)){
		dedupe_info->bloom_filter_noexist++;
		for(i = 0; i < dedupe_info->bloom_filter_hash_fun_count; i++){
			printk("bloom filter add:%d\t", test_bit((*pos)&dedupe_info->bloom_filter_mask, (long unsigned int*)dedupe_info->bloom_filter));
			set_bit((*pos)&dedupe_info->bloom_filter_mask, (long unsigned int*)dedupe_info->bloom_filter);
			printk("%d\n", test_bit((*pos)&dedupe_info->bloom_filter_mask, (long unsigned int*)dedupe_info->bloom_filter));
			pos++;
		}
		return 0;
	}
	dedupe_info->bloom_filter_exist++;
	return 0;
}


int dedupe_rb_cmp(u8 hash1[], u8 hash2[])
{
	int i;
	for(i=0;i<16;i++)
	{
		if(hash1[i]>hash2[i])
		{
			return 1;
		}
		else if(hash1[i]<hash2[i])
		{
			return -1;
		}
	}
	return 0;
}

struct dedupe_rb_node *dedupe_rb_search_addr(struct rb_root *root, block_t addr)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct dedupe_rb_node *data = container_of(node, struct dedupe_rb_node, node_addr);
		if (addr < data->dedupe.addr)
			node = node->rb_left;
		else if (addr > data->dedupe.addr)
			node = node->rb_right;
		else
			return data;
		}
	return NULL;
}

int dedupe_rb_delete(struct dedupe_info *dedupe_info, block_t addr)
{
	struct rb_root *root_addr, *root_hash;
	struct dedupe_rb_node *dedupe_rb_node;
	root_addr = &dedupe_info->dedupe_rb_root_addr;
	root_hash = &dedupe_info->dedupe_rb_root_hash;
	dedupe_rb_node = dedupe_rb_search_addr(root_addr, addr);
	if(dedupe_rb_node)
	{
		dedupe_info->logical_blk_cnt--;
		if(!--dedupe_rb_node->dedupe.ref) {
			spin_lock(&dedupe_info->lock);
			rb_erase(&dedupe_rb_node->node_hash, root_hash);
			rb_erase(&dedupe_rb_node->node_addr, root_addr);
			dedupe_rb_node->dedupe.ref = -1;
			dedupe_rb_node_free(dedupe_info, dedupe_rb_node);
			spin_unlock(&dedupe_info->lock);
			//kfree(dedupe_rb_node);
			dedupe_info->physical_blk_cnt--;
			return 0;
		}
		else
			return dedupe_rb_node->dedupe.ref;
	}
	else return -1;
}

struct dedupe_rb_node *dedupe_rb_hash_insert(struct rb_root *root_hash, struct dedupe_rb_node *data)
{
	struct rb_node **new, *parent = NULL;

	new = &(root_hash->rb_node);
	while (*new) {
		struct dedupe_rb_node *this = container_of(*new, struct dedupe_rb_node, node_hash);
		int result = dedupe_rb_cmp(data->dedupe.hash, this->dedupe.hash);

		parent = *new;
		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else
			return this;
	}
	rb_link_node(&data->node_hash, parent, new);
	rb_insert_color(&data->node_hash, root_hash);

	return data;
}

int dedupe_rb_addr_insert(struct rb_root *root_addr, struct dedupe_rb_node *data)
{
	struct rb_node **new, *parent = NULL;
	new = &(root_addr->rb_node);
	while (*new) {
		struct dedupe_rb_node *this = container_of(*new, struct dedupe_rb_node, node_addr);
		parent = *new;
		if (this->dedupe.addr > data->dedupe.addr)
			new = &((*new)->rb_left);
		else if (this->dedupe.addr < data->dedupe.addr)
			new = &((*new)->rb_right);
		else
			return 1;
		}

	rb_link_node(&data->node_addr, parent, new);
	rb_insert_color(&data->node_addr, root_addr);

	return 0;
}

struct dedupe_rb_node *dedupe_rb_node_alloc(struct dedupe_info *dedupe_info)
{
	int i,j;
	struct dedupe_rb_node *t;

	if(dedupe_info->dedupe_rb_node_count>0)
	{
		dedupe_info->dedupe_rb_node_count--;
		for(i=dedupe_info->alloc_page_point; i< PAGE_COUNT;i++)
		{
			t = ((struct dedupe_rb_node *)dedupe_info->dedupe_rb_node_page_base[i]);
			for(j=dedupe_info->alloc_point; j< DEDUPE_RB_PER_BLOCK; j++)
			{
				if(t[j].dedupe.ref == -1)
				{
					dedupe_info->alloc_page_point = i;
					dedupe_info->alloc_point = j + 1;
					return &t[j];
				}
			}
			dedupe_info->alloc_point = 0;
		}
		dedupe_info->alloc_point = 0;
		for(i=0; i<= dedupe_info->alloc_page_point;i++)
		{
			t = ((struct dedupe_rb_node *)dedupe_info->dedupe_rb_node_page_base[i]);
			for(j=dedupe_info->alloc_point; j< DEDUPE_RB_PER_BLOCK; j++)
			{
				if(t[j].dedupe.ref == -1)
				{
					dedupe_info->alloc_page_point = i;
					dedupe_info->alloc_point = j + 1;
					return &t[j];
				}
			}
		}
	}
	//printk("kmalloc\n");
	t = kmalloc(sizeof(struct dedupe_rb_node), GFP_KERNEL);
	t->free_flag = 1;
	return t;
}

void dedupe_rb_node_free(struct dedupe_info *dedupe_info, struct dedupe_rb_node *dedupe_rb_node)
{
	if(unlikely(dedupe_rb_node->free_flag))
	{
		kfree(dedupe_rb_node);
		return;
	}
	dedupe_info->dedupe_rb_node_count++;
	dedupe_rb_node->dedupe.ref = -1;
}

int init_dedupe_info(struct dedupe_info *dedupe_info)
{
	int ret = 0;
	int i, j;
	struct dedupe_rb_node *t;
	dedupe_info->digest_len = 16;
	spin_lock_init(&dedupe_info->lock);
	INIT_LIST_HEAD(&dedupe_info->queue);
	dedupe_info->dedupe_segment_count = DEDUPE_SEGMENT_COUNT;
	dedupe_info->tfm = crypto_alloc_shash("md5", 0, 0);
	dedupe_info->crypto_shash_descsize = crypto_shash_descsize(dedupe_info->tfm);
	dedupe_info->dedupe_rb_root_hash = RB_ROOT;
	dedupe_info->dedupe_rb_root_addr = RB_ROOT;
	printk("sizeof(struct dedupe_rb_node):%lu PAGE_COUNT:%lu vmalloc:%lu\n",sizeof(struct dedupe_rb_node), PAGE_COUNT,PAGE_COUNT*sizeof(char *));
	dedupe_info->dedupe_rb_node_page_base = vmalloc(PAGE_COUNT*sizeof(char *));
	dedupe_info->alloc_page_point=0;
	dedupe_info->alloc_point=0;
	dedupe_info->free_page_point=0;
	dedupe_info->free_point=0;
	dedupe_info->dedupe_rb_node_count = DATA_SIZE*DEDUPE_PER_DATA_SIZE;
	dedupe_info->dynamic_logical_blk_cnt = 0;
	dedupe_info->dynamic_physical_blk_cnt = 0;
	for(i=0;i<PAGE_COUNT;i++)
	{
		dedupe_info->dedupe_rb_node_page_base[i] = (char *)__get_free_page(GFP_KERNEL);
		t = ((struct dedupe_rb_node *)dedupe_info->dedupe_rb_node_page_base[i]);
		for(j=0; j< DEDUPE_RB_PER_BLOCK; j++)
		{
			t[j].dedupe.ref = -1;
			t[j].free_flag = 0;
		}
	}

	dedupe_info->bloom_filter_exist = 0;
	dedupe_info->bloom_filter_noexist = 0;
	dedupe_info->bloom_filter_mask = ((1UL << (10 + 10)) - 1);
	dedupe_info->bloom_filter = vmalloc(dedupe_info->bloom_filter_mask + 1);
	memset(dedupe_info->bloom_filter, 0, dedupe_info->bloom_filter_mask + 1);
	dedupe_info->bloom_filter_hash_fun_count = 4;
	printk("DEDUPE_SEGMENT_COUNT=%d\tDEDUPE_PER_BLOCK=%d\n", DEDUPE_SEGMENT_COUNT, (int)DEDUPE_PER_BLOCK);
    printk("bloom_filter=%x\n",(dedupe_info->bloom_filter_mask + 1));
	return ret;
}

void exit_dedupe_info(struct dedupe_info *dedupe_info)
{
	int i;
	vfree(dedupe_info->bloom_filter);
	crypto_free_shash(dedupe_info->tfm);
	for(i=0;i<PAGE_COUNT;i++) 
		free_page((unsigned long) dedupe_info->dedupe_rb_node_page_base[i] );
}

