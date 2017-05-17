#ifndef _DEDUPE_H
#define _DEDUPE_H

#define DEDUPE_SEGMENT_COUNT 98
#define DEDUPE_PER_BLOCK (PAGE_CACHE_SIZE/sizeof(struct dedupe))

#define DATA_SIZE 10
#define DEDUPE_PER_DATA_SIZE (256*1024)
#define DEDUPE_RB_PER_BLOCK (PAGE_CACHE_SIZE/sizeof(struct dedupe_rb_node))
#define PAGE_COUNT (DATA_SIZE*(DEDUPE_PER_DATA_SIZE/DEDUPE_RB_PER_BLOCK + 1))

typedef u32 block_t;

struct dedupe
{
	block_t addr;
	int ref;
	u8 hash[16];
};

struct dedupe_info
{
	int digest_len;
	unsigned int logical_blk_cnt;
	unsigned int physical_blk_cnt;
	unsigned int dynamic_logical_blk_cnt;
	unsigned int dynamic_physical_blk_cnt;
	unsigned int dedupe_segment_count;
	unsigned int dedupe_block_count;
	struct list_head queue;
	spinlock_t lock;
	struct crypto_shash *tfm;
	unsigned int crypto_shash_descsize;
	struct rb_root dedupe_rb_root_hash;
	struct rb_root dedupe_rb_root_addr;
	unsigned int alloc_page_point;
	unsigned int alloc_point;
	unsigned int free_page_point;
	unsigned int free_point;
	char **dedupe_rb_node_page_base;
	int dedupe_rb_node_count;

	unsigned int bloom_filter_mask;
	unsigned char *bloom_filter;
	unsigned int bloom_filter_hash_fun_count;
	unsigned int bloom_filter_exist;
	unsigned int bloom_filter_noexist;
};

struct dedupe_rb_node {
	struct rb_node node_hash;
	struct rb_node node_addr;
	struct dedupe dedupe;
	int free_flag;
};

extern struct dedupe_rb_node *dedupe_rb_hash_insert(struct rb_root *root_hash, struct dedupe_rb_node *data);
extern int dedupe_rb_delete(struct dedupe_info *dedupe_info, block_t addr);
extern int dedupe_rb_addr_insert(struct rb_root *root_addr, struct dedupe_rb_node *data);
extern int f2fs_dedupe_calc_hash(struct page *p, u8 hash[], struct dedupe_info *dedupe_info);
extern int init_dedupe_info(struct dedupe_info *dedupe_info);
extern void exit_dedupe_info(struct dedupe_info *dedupe_info);
extern struct dedupe_rb_node *dedupe_rb_node_alloc(struct dedupe_info *dedupe_info);
extern void dedupe_rb_node_free(struct dedupe_info *dedupe_info, struct dedupe_rb_node *dedupe_rb_node);
extern int dedupe_bloom_filter(u8 hash[], struct dedupe_info* dedupe_info);
extern int dedupe_bloom_filter_add(u8 hash[], struct dedupe_info* dedupe_info);
extern int dedupe_bloom_filter_del(u8 hash[], struct dedupe_info* dedupe_info);

#endif

