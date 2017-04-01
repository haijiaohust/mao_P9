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
			rb_erase(&dedupe_rb_node->node_hash, root_hash);
			rb_erase(&dedupe_rb_node->node_addr, root_addr);
			kfree(dedupe_rb_node);
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
	dedupe_info->dedupe_segment_count = DEDUPE_SEGMENT_COUNT;
	dedupe_info->tfm = crypto_alloc_shash("md5", 0, 0);
	dedupe_info->crypto_shash_descsize = crypto_shash_descsize(dedupe_info->tfm);
	dedupe_info->dedupe_rb_root_hash = RB_ROOT;
	dedupe_info->dedupe_rb_root_addr = RB_ROOT;
	return ret;
}

void exit_dedupe_info(struct dedupe_info *dedupe_info)
{
	crypto_free_shash(dedupe_info->tfm);
}

