#ifndef _DEDUPE_F2FS_
#define _DEDUPE_F2FS_

#include <linux/pagemap.h>
#include <crypto/hash.h>
#include <crypto/md5.h>
#include <crypto/sha.h>
#include <crypto/algapi.h>
#include "dedupe.h"
#include <linux/f2fs_fs.h>
#include <linux/vmalloc.h>

#define DEDUPE_BTREE_DEGREE 73
#define DEDUPE_SEGMENT_COUNT 24

//#define DEBUG_BTREE 1

typedef u32 block_t;

struct dedupe{
	block_t addr;
	unsigned int ref;
	u8 hash[16];
};

struct dedupe_btree_block{
	unsigned short keynum;
	unsigned short leaf;	//1 is leaf, 0 is not
	struct dedupe_btree_block* child_addr[2 * DEDUPE_BTREE_DEGREE];
	struct dedupe dedupe[2 * DEDUPE_BTREE_DEGREE - 1];
}__packed;
struct dedupe_btree{
	unsigned short keynum;
	unsigned short leaf;	//1 is leaf, 0 is not
	block_t child_addr[2 * DEDUPE_BTREE_DEGREE];
	struct dedupe dedupe[2 * DEDUPE_BTREE_DEGREE - 1];
}__packed;


struct dedupe_btree_root{
	struct dedupe_btree_block* root;
};

struct dedupe_btree_search_result{
	struct dedupe_btree_block* addr;
	int seq;
};

struct dedupe_info{
	unsigned int logical_blk_cnt;
	unsigned int physical_blk_cnt;
	unsigned int dynamic_logical_blk_cnt;
	unsigned int dynamic_physical_blk_cnt;
	block_t dedupe_base_addr;
	unsigned int dedupe_segment_count;
	unsigned int dedupe_block_count;
	char* dedupe_bitmap;
	char* dedupe_ditry_bitmap;
	unsigned int dedupe_bitmap_size;
	int digest_len;
	unsigned int crypto_shash_descsize;
	spinlock_t dedupe_lock;
	struct crypto_shash *tfm;
	struct dedupe_btree_root* btree_root;
};

void print_hash(u8 *hash);
int f2fs_dedupe_calc_hash(struct page *p, u8 hash[], struct dedupe_info *dedupe_info);
struct dedupe_btree_search_result dedupe_btree_search_hash(struct dedupe_info* dedupe_info, u8 hash[], int flag);
int dedupe_btree_insert_hash(struct dedupe_info* dedupe_info, u8 hash[], block_t addr);
void dedupe_destory(struct dedupe_btree_root* root);
void dedupe_btree_print(struct dedupe_btree_block* root, int layer);
void init_dedupe_info(struct dedupe_info *dedupe_info);
void exit_dedupe_info(struct dedupe_info *dedupe_info);

#endif
