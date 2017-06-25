#ifndef _DEDUPE_H
#define _DEDUPE_H

//#define DEDUPE_RB_TREE_F2FS 1
#define DEDUPE_LIST_F2FS 1
#define F2FS_BLOOM_FILTER 1
#define F2FS_REVERSE_ADDR 1

#define DEDUPE_SEGMENT_COUNT 24
#define DEDUPE_PER_BLOCK (PAGE_CACHE_SIZE/sizeof(struct dedupe))
#define DEDUPE_RELI_NUM 10000

typedef u32 block_t;

struct dedupe
{
	block_t addr;
	int ref;
	u8 hash[16];
};

struct dedupe_reli
{
	block_t addr1;
	block_t addr2;
	u8 hash[16];
};

#ifdef DEDUPE_RB_TREE_F2FS
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
	struct dedupe_reli *dedupe_reli;
};

struct dedupe_rb_node {
	struct rb_node node_hash;
	struct rb_node node_addr;
	struct dedupe dedupe;
};

extern struct dedupe_rb_node *dedupe_rb_hash_insert(struct rb_root *root_hash, struct dedupe_rb_node *data);
extern int dedupe_rb_delete(struct dedupe_info *dedupe_info, block_t addr);
extern int dedupe_rb_addr_insert(struct rb_root *root_addr, struct dedupe_rb_node *data);
extern int init_dedupe_info(struct dedupe_info *dedupe_info);
extern void exit_dedupe_info(struct dedupe_info *dedupe_info);
#endif 

#ifdef DEDUPE_LIST_F2FS
struct dedupe_info
{
	int digest_len;
#ifdef F2FS_BLOOM_FILTER
	unsigned int bloom_filter_mask;
	unsigned int *bloom_filter;
	unsigned int bloom_filter_hash_fun_count;
#endif
	unsigned int logical_blk_cnt;
	unsigned int physical_blk_cnt;
	unsigned int dynamic_logical_blk_cnt;
	unsigned int dynamic_physical_blk_cnt;
	struct dedupe* dedupe_md;
	char *dedupe_md_dirty_bitmap;	/*bitmap for dirty dedupe blocks*/
	char *dedupe_bitmap;				/*bitmap for dedupe checkpoint*/
	unsigned int dedupe_segment_count;
	unsigned int dedupe_bitmap_size;	/*bitmap size of dedupe_md_dirty_bitmap&dedupe_bitmap*/
	unsigned int dedupe_size;			/*size of dedupes in memory*/
	unsigned int dedupe_block_count;
	struct dedupe* last_delete_dedupe;
	struct list_head queue;
	spinlock_t lock;
	struct crypto_shash *tfm;
	unsigned int crypto_shash_descsize;
	struct dedupe_reli *dedupe_reli;
#ifdef F2FS_REVERSE_ADDR
	int *reverse_addr;
#endif
};

extern struct dedupe *f2fs_dedupe_search(u8 hash[], struct dedupe_info *dedupe_info);
extern int f2fs_dedupe_add(u8 hash[], struct dedupe_info *dedupe_info, block_t addr);
#ifdef F2FS_BLOOM_FILTER
extern void init_f2fs_dedupe_bloom_filter(struct dedupe_info *dedupe_info);
#endif
extern int f2fs_dedupe_delete_addr(block_t addr, struct dedupe_info *dedupe_info);
extern void set_dedupe_dirty(struct dedupe_info *dedupe_info, struct dedupe *dedupe);
extern struct dedupe *f2fs_dedupe_search_by_addr(block_t addr, struct dedupe_info *dedupe_info);
extern int init_dedupe_info(struct dedupe_info *dedupe_info);
extern void exit_dedupe_info(struct dedupe_info *dedupe_info);
#endif
extern int f2fs_dedupe_calc_hash(struct page *p, u8 hash[], struct dedupe_info *dedupe_info);
extern void f2fs_dedupe_reli_add(u8 hash[], struct dedupe_info *dedupe_info, block_t addr, int add_type);
extern int f2fs_dedupe_reli_del_addr(u8 hash[], struct dedupe_info *dedupe_info, int del_type);
extern struct dedupe_reli *f2fs_dedupe_reli_search_by_hash(u8 hash[], struct dedupe_info *dedupe_info);
#endif

