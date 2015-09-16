#ifndef __RCYH_YHRBTREE_H__
#define __RCYH_YHRBTREE_H__
#ifdef __cplusplus
extern "C"
{
#endif
#pragma pack(push)
#pragma pack(4)
#pragma pack(pop)

/*
  Container Of Red Black Trees
  (C) 2011 Hong Yuan
 */


/**********************************************************/
#ifndef offsetof
#define offsetof(type, member) \
	(size_t)&(((type *)0)->member)
#endif

#ifndef container_of
#define container_of(ptr, type, member)  \
	({\
		const typeof(((type *)0)->member) * __mptr = (ptr);\
		(type *)((char *)__mptr - offsetof(type, member)); \
	})
#endif
/**********************************************************/

// rbtree.h header codes
// rbtree.h
// {{{
// rbtree.h

         /* This is linux/include/linux/rbtree.h */

/*
  Red Black Trees
  (C) 1999  Andrea Arcangeli <andrea@suse.de>
  
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

  linux/include/linux/rbtree.h

  To use rbtrees you'll have to implement your own insert and search cores.
  This will avoid us to use callbacks and to drop drammatically performances.
  I know it's not the cleaner way,  but in C (not in C++) to get
  performances and genericity...

  Some example of insert and search follows here. The search is a plain
  normal search over an ordered tree. The insert instead must be implemented
  in two steps: First, the code must insert the element in order as a red leaf
  in the tree, and then the support library function rb_insert_color() must
  be called. Such function will do the not trivial work to rebalance the
  rbtree, if necessary.

-----------------------------------------------------------------------
static inline struct page * rb_search_page_cache(struct inode * inode,
						 unsigned long offset)
{
	struct rb_node * n = inode->i_rb_page_cache.rb_node;
	struct page * page;

	while (n)
	{
		page = rb_entry(n, struct page, rb_page_cache);

		if (offset < page->offset)
			n = n->rb_left;
		else if (offset > page->offset)
			n = n->rb_right;
		else
			return page;
	}
	return NULL;
}

static inline struct page * __rb_insert_page_cache(struct inode * inode,
						   unsigned long offset,
						   struct rb_node * node)
{
	struct rb_node ** p = &inode->i_rb_page_cache.rb_node;
	struct rb_node * parent = NULL;
	struct page * page;

	while (*p)
	{
		parent = *p;
		page = rb_entry(parent, struct page, rb_page_cache);

		if (offset < page->offset)
			p = &(*p)->rb_left;
		else if (offset > page->offset)
			p = &(*p)->rb_right;
		else
			return page;
	}

	rb_link_node(node, parent, p);

	return NULL;
}

static inline struct page * rb_insert_page_cache(struct inode * inode,
						 unsigned long offset,
						 struct rb_node * node)
{
	struct page * ret;
	if ((ret = __rb_insert_page_cache(inode, offset, node)))
		goto out;
	rb_insert_color(node, &inode->i_rb_page_cache);
 out:
	return ret;
}
-----------------------------------------------------------------------
*/

#ifndef	_LINUX_RBTREE_H
#define	_LINUX_RBTREE_H

#include <stddef.h>

struct rb_node
{
	unsigned long  rb_parent_color;
#define	RB_RED		0
#define	RB_BLACK	1
	struct rb_node *rb_right;
	struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));
    /* The alignment might seem pointless, but allegedly CRIS needs it */


/* Callback of generic container */
typedef const int   cmp_func_t(const void * pkey1, const void * pkey2);
typedef const void* getkey_func_t(const void * pdata);

/*
 * Generic container:
 *   Root of Red Black Trees
 *   Manager information
 */
typedef struct rb_root
{
	/*  
	 *  Root of Red Black Trees
	 */
	struct rb_node *rb_node;
	/* 
	 *  callback of comparison function for node
	 */
	cmp_func_t     *cmp;        
	/* 
	 *  callback of get key value for node
	 */ 
	getkey_func_t  *getkey;   
} rb_root_t;


#define rb_parent(r)   ((struct rb_node *)((r)->rb_parent_color & ~3))
#define rb_color(r)   ((r)->rb_parent_color & 1)
#define rb_is_red(r)   (!rb_color(r))
#define rb_is_black(r) rb_color(r)
#define rb_set_red(r)  do { (r)->rb_parent_color &= ~1; } while (0)
#define rb_set_black(r)  do { (r)->rb_parent_color |= 1; } while (0)

static 
inline void rb_set_parent(struct rb_node *rb, struct rb_node *p)
{
	rb->rb_parent_color = (rb->rb_parent_color & 3) | (unsigned long)p;
}
static 
inline void rb_set_color(struct rb_node *rb, int color)
{
	rb->rb_parent_color = (rb->rb_parent_color & ~1) | color;
}

#define RB_ROOT	(struct rb_root) { NULL, }
#define	rb_entry(ptr, type, member) container_of(ptr, type, member)

#define RB_EMPTY_ROOT(root)	((root)->rb_node == NULL)
#define RB_EMPTY_NODE(node)	(rb_parent(node) == node)
#define RB_CLEAR_NODE(node)	(rb_set_parent(node, node))

extern void rb_insert_color(struct rb_node *, struct rb_root *);
extern void rb_erase(struct rb_node *, struct rb_root *);

typedef void (*rb_augment_f)(struct rb_node *node, void *data);

extern void rb_augment_insert(struct rb_node *node,
			      rb_augment_f func, void *data);
extern struct rb_node *rb_augment_erase_begin(struct rb_node *node);
extern void rb_augment_erase_end(struct rb_node *node,
				 rb_augment_f func, void *data);

/* Find logical next and previous nodes in a tree */
extern struct rb_node *rb_next(const struct rb_node *);
extern struct rb_node *rb_prev(const struct rb_node *);
extern struct rb_node *rb_first(const struct rb_root *);
extern struct rb_node *rb_last(const struct rb_root *);

/* Fast replacement of a single node without remove/rebalance/add/rebalance */
extern void rb_replace_node(struct rb_node *victim, struct rb_node *_new, 
			    struct rb_root *root);

static 
inline void rb_link_node(struct rb_node * node, struct rb_node * parent,
				struct rb_node ** rb_link)
{
	node->rb_parent_color = (unsigned long )parent;
	node->rb_left = node->rb_right = NULL;

	*rb_link = node;
}

#endif	/* _LINUX_RBTREE_H */

// rbtree.h
// }}}
// rbtree.h
// rbtree.h header codes


 
/*
 * Generic container:
 *   Leaf node of Red Black Trees
 *   Node information and data
 */
typedef struct rb_node_data
{
	struct rb_node rb_node;
	unsigned long size;
	unsigned char data[];
}rb_node_t;
typedef rb_node_t rb_node_data_t;
typedef rb_node_t rb_nd_t;

/*
 * Initializing rbtree root
 */
void rbt_init(struct rb_root *root, getkey_func_t * getkey , cmp_func_t *cmp);
/*
 * stack alloc rbtree node-data
 */

struct rb_node_data *rbt_node_new(size_t size);
/*
 * free rbtree node-data
 */
void rbt_node_free(struct rb_node_data *node);

/*
 * node field location
 */
struct rb_node_data* get_node_entry_from(void *data_field);
int 	get_node_data_size(void *data_field);

void * get_data_pointer(struct rb_node_data *rnd);
int    get_data_size(struct rb_node_data *rnd);

/*
 * Search key node from rbtree
 */
struct rb_node_data * 
	rbt_search(struct rb_root *root, const void* key);

/*
 * Insert key node into rbtree
 */
int rbt_insert(struct rb_root *root, struct rb_node_data *cont);

/*
 * Delete the key node from rbtree
 *     delete node from rbtree, return node pointer
 */
struct rb_node_data * 
	rbt_delete(struct rb_root *root, const void *key);

/*
 * Erase the node from rbtree, return deleted node pointer
 *   *** use with caution, node must exist in rbtree ***
 *   *** example: ***
  	   struct rb_node_data *node;
	   node = rbt_search(&root, key);
	   if (node) 
	   {
	   	// use node
		// action code
		rbt_erase(&root, node);
		rbt_node_free(node);
		node = NULL;
	   }
 *
 */
void rbt_erase(struct rb_root *root, struct rb_node_data *node);

/*
 * Replace the key node from rbtree for new rb_node_data
 *    replace node from rbtree, return old node pointer
 */
struct rb_node_data * rbt_replace(struct rb_root *root, 
		struct rb_node_data *current_node);

/*
 * Traversing the rbtree, all the node data call action 
 */
int rbt_inorder(struct rb_root *root, void *pedata, 
	int (*action)(void *pndata, void *pedata), int *action_succ_ret);

/*
 * clear the rbtree
 * 	callback the action before the free of the node data
 */
int rbt_clear(struct rb_root *root, void *pedata, 
	int (*action)(void *pndata, void *pedata), int *action_succ_ret);

/*
 * Get first and last node from rbtree
 */
struct rb_node_data * rbt_node_first(struct rb_root *root);
struct rb_node_data * rbt_node_last(struct rb_root *root);

/*
 * Get first and last data of node from rbtree
 */
void * rbt_data_first(struct rb_root *root);
void * rbt_data_last(struct rb_root *root);

/*
 * Get next and prev node from rbtree
 */
struct rb_node_data 
	*rbt_node_next(struct rb_node_data *data_node);
struct rb_node_data 
	*rbt_node_prev(struct rb_node_data *data_node);

/*
 * Get next and prev data of node from rbtree
 */
void *rbt_data_next(struct rb_node_data *data_node);
void *rbt_data_prev(struct rb_node_data *data_node);



#ifdef __cplusplus
}
#endif
#endif /* __RCYH_YHRBTREE_H__ */
