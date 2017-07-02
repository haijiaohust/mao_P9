#include "f2fs.h"

void print_hash(u8 *hash)
{
	int i;
	for(i = 0; i < 16; i++)
		printk("%x", hash[i]);
	printk("\n");
}

int f2fs_dedupe_calc_hash(struct page *p, u8 *hash, struct dedupe_info *dedupe_info)
{
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

	return ret;
}

void dedupe_create_btree_root(struct dedupe_info* dedupe_info)
{
	struct dedupe_btree_root *btree_root = kzalloc(sizeof(struct dedupe_btree_root), GFP_KERNEL);
	if(!btree_root){
		printk("alloc btree_root error\n");
		return;
	}
	btree_root->root = NULL;
	dedupe_info->btree_root = btree_root;
#ifdef DEBUG_BTREE
	if(!dedupe_info->btree_root){
		printk("root_dedupe: 2\n");
		if(!dedupe_info->btree_root->root)
			printk("root_dedupe: 20\n");
	}
#endif
}

struct dedupe_btree_block* dedupe_create_btree_block(void)
{
	struct dedupe_btree_block *p = kzalloc(sizeof(struct dedupe_btree_block), GFP_KERNEL);
	if(!p){
		printk("alloc btree_block error\n");
		return NULL;
	}
	memset(p, 0, sizeof(struct dedupe_btree_block));
	p->leaf = 1;
	p->keynum = 0;
	return p;
}

int dedupe_hash_cmp(u8 *hash1, u8 *hash2)
{
	return memcmp(hash1, hash2, 16);
}

struct dedupe_btree_search_result __dedupe_btree_search_hash(
		struct dedupe_info *dedupe_info, struct dedupe_btree_block *btree_block, u8 *hash)
{
	int i, ret;
	struct dedupe_btree_block *p = btree_block;
	i = 0;
	while(i < p->keynum && ((ret = dedupe_hash_cmp(hash, p->dedupe[i].hash)) > 0))
		i++;
	if(i < p->keynum && ret == 0)
		return (struct dedupe_btree_search_result){p, i};
	if(p->leaf)
		return (struct dedupe_btree_search_result){NULL, -1};
	return __dedupe_btree_search_hash(dedupe_info, p->child_addr[i], hash);
}

struct dedupe_btree_search_result dedupe_btree_search_hash(
	struct dedupe_info *dedupe_info, u8 *hash, int flag)
{
	int i, ret;
	struct dedupe_btree_block* p = NULL;
	struct dedupe_btree_root* btree_root = dedupe_info->btree_root;
	struct dedupe_btree_search_result result = {
		.addr = NULL,
		.seq = -1,
	};
#ifdef DEBUG_BTREE
	printk("search hash\n");
	print_hash(hash);
#endif
	if(!btree_root){
		printk("dedupe_btree_search_hash: btree_root error\n");
		return (struct dedupe_btree_search_result){NULL, -1};
	}
	p = btree_root->root;
	if(!p)
		return (struct dedupe_btree_search_result){NULL, -1};
	i = 0;
	while(i < p->keynum && (ret = dedupe_hash_cmp(hash, p->dedupe[i].hash)) > 0)
		i++;
	if(i < p->keynum && ret == 0){
		if(flag)
			p->dedupe[i].ref++;
		return (struct dedupe_btree_search_result){p, i};
	}
	if(p->leaf)
		return (struct dedupe_btree_search_result){NULL, -1};
	result = __dedupe_btree_search_hash(dedupe_info, p->child_addr[i], hash);
	if(result.seq != -1 && flag)
		result.addr->dedupe[i].ref++;
	return result;
}

void dedupe_btree_insert_hash_split(
	struct dedupe_btree_block *x, struct dedupe_btree_block *y, int index)
{
	int i;
	struct dedupe_btree_block *z = dedupe_create_btree_block();
	z->leaf = y->leaf;
	z->keynum = DEDUPE_BTREE_DEGREE - 1;
	for(i = 0; i < DEDUPE_BTREE_DEGREE - 1; i++){
		memcpy(&z->dedupe[i], &y->dedupe[DEDUPE_BTREE_DEGREE + i], sizeof(struct dedupe));
		memset(&y->dedupe[DEDUPE_BTREE_DEGREE + i], 0, sizeof(struct dedupe));
	}
	if(!y->leaf)
		for(i = 0; i < DEDUPE_BTREE_DEGREE; i++){
			z->child_addr[i] = y->child_addr[DEDUPE_BTREE_DEGREE + i];
			y->child_addr[DEDUPE_BTREE_DEGREE + i] = NULL;
		}
	y->keynum = DEDUPE_BTREE_DEGREE - 1;
	for(i = x->keynum; i > index; i--)
		x->child_addr[i + 1] = x->child_addr[i];
	x->child_addr[i + 1] = z;
	for(i = x->keynum - 1; i >= index; i--)
		memcpy(&x->dedupe[i + 1], &x->dedupe[i], sizeof(struct dedupe));
	memcpy(&x->dedupe[i + 1], &y->dedupe[DEDUPE_BTREE_DEGREE - 1], sizeof(struct dedupe));
	memset(&y->dedupe[DEDUPE_BTREE_DEGREE - 1], 0, sizeof(struct dedupe));
	x->keynum++;
}

void dedupe_btree_insert_hash_notfull(struct dedupe_btree_block *x, u8 *hash, block_t addr)
{
#ifdef DEBUG_BTREE
	printk("insert hash: notfull\n");
#endif
	struct dedupe_btree_block *p = NULL;
	int i = x->keynum - 1;
	if(x->leaf){
		while(i >= 0 && dedupe_hash_cmp(hash, x->dedupe[i].hash) < 0){
			memcpy(&x->dedupe[i + 1], &x->dedupe[i], sizeof(struct dedupe));
			i--;
		}
		memcpy(x->dedupe[i + 1].hash, hash, 16);
		x->dedupe[i + 1].ref = 1;
		x->dedupe[i + 1].addr = addr;
		x->keynum++;
	}
	else{
		while(i >= 0 && dedupe_hash_cmp(hash, x->dedupe[i].hash) < 0)
			i--;
		i++;
		p = x->child_addr[i];
		if(p->keynum == (2 * DEDUPE_BTREE_DEGREE - 1)){
			dedupe_btree_insert_hash_split(x, p, i);
			if(dedupe_hash_cmp(hash, x->dedupe[i].hash) > 0)
				i++;
		}
		dedupe_btree_insert_hash_notfull(x->child_addr[i], hash, addr);
	}
}

int dedupe_btree_insert_hash(struct dedupe_info* dedupe_info, u8 *hash, block_t addr)
{
	struct dedupe_btree_block *p = NULL;
	struct dedupe_btree_block *node = NULL;
	struct dedupe_btree_root *btree_root = dedupe_info->btree_root;
#ifdef DEBUG_BTREE
	printk("insert hash\n");
#endif
	if(!btree_root){
		printk("dedupe_btree_insert_hash: btree_root error\n");
		return -1;
	}
	if(!btree_root->root)
		btree_root->root = dedupe_create_btree_block();

	p = btree_root->root;
	if(p->keynum == (2 * DEDUPE_BTREE_DEGREE - 1)){
#ifdef DEBUG_BTREE
			printk("insert hash: full to split\n");
#endif
		node = dedupe_create_btree_block();
		btree_root->root = node;
		node->child_addr[0] = p;
		node->leaf = 0;
		dedupe_btree_insert_hash_split(node, p, 0);
		dedupe_btree_insert_hash_notfull(node, hash, addr);
	}
	else dedupe_btree_insert_hash_notfull(p, hash, addr);
#ifdef DEBUG_BTREE
	if(!dedupe_info->btree_root){
		printk("insert_dedupe: 3\n");
		if(!dedupe_info->btree_root)
			printk("insert_dedupe: 30\n");
	}
#endif
	return 0;
}

void dedupe_btree_print(struct dedupe_btree_block *root, int layer)
{
	int i;
	struct dedupe_btree_block *p = root;
	if(!p){
		printk("dedupe_btree_print, root is NULL\n");
		return;
	}
	if(p){
		printk("dedupe_btree_print, begin\n");
		printk("dedupe_btree_print: layer=%d num=%u leaf=%u\n", layer, p->keynum, p->leaf);
		for(i = 0; i < p->keynum; i++){
			print_hash(p->dedupe[i].hash);
			printk("%u %u\n", p->dedupe[i].addr, p->dedupe[i].ref);
		}
		printk("%p\n", p);
		for(i = 0; i < 2 * DEDUPE_BTREE_DEGREE; i++)
			printk("%p\n", p->child_addr[i]);
		printk("dedupe_btree_print, end\n");
		layer++;
		for(i = 0; i <= p->keynum; i++)
			if(p->child_addr[i])
				dedupe_btree_print(p->child_addr[i], layer);
	}
	else printk("print: the tree is empty\n");
}

void __dedupe_destory(struct dedupe_btree_block* block)
{
	int i;
	if(block->child_addr[0]->leaf){
		for(i = 0; i <= block->keynum; i++)
			kfree(block->child_addr[i]);
	}
	else{
		for(i = 0; i <= block->keynum; i++)
			__dedupe_destory(block->child_addr[i]);
	}
	kfree(block);
}

void dedupe_destory(struct dedupe_btree_root* root)
{
	struct dedupe_btree_block* p = NULL;
	if(!root){
		printk("destory: the tree is error\n");
		return;
	}
	p = root->root;
	if(!p){
		printk("destory: the tree is empty\n");
		return;
	}
	if(p->leaf)
		kfree(p);
	else __dedupe_destory(p);
	
	kfree(root);
}

void init_dedupe_info(struct dedupe_info *dedupe_info)
{
	struct dedupe_btree_block* p = dedupe_create_btree_block();
	printk("btree_size_block %lu\n", sizeof(struct dedupe_btree_block));
	printk("btree_size %lu\n", sizeof(struct dedupe_btree));
	printk("btree_size %p %p %p %p %p\n", p, &p->keynum, &p->leaf, &p->child_addr, &p->dedupe);
	kfree(p);
	dedupe_info->digest_len = 16;
	dedupe_info->tfm = crypto_alloc_shash("md5", 0, 0);
	dedupe_info->crypto_shash_descsize = crypto_shash_descsize(dedupe_info->tfm);
	dedupe_info->dynamic_logical_blk_cnt = 0;
	dedupe_info->dynamic_physical_blk_cnt = 0;
	spin_lock_init(&dedupe_info->dedupe_lock);
	dedupe_create_btree_root(dedupe_info);
#ifdef DEBUG_BTREE
	if(!dedupe_info->btree_root->root){
		printk("init_dedupe: 1\n");
		if(!dedupe_info->btree_root){
			printk("init_dedupe: 10\n");
		}
	}
	if(!dedupe_info->btree_root){
		printk("init_dedupe: 100\n");
	}
#endif
}

void exit_dedupe_info(struct dedupe_info *dedupe_info)
{
	dedupe_destory(dedupe_info->btree_root);
}

