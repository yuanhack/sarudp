#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "yhrbtree.h"

#include <assert.h>

#define AUTHOR   "Yuan Hong"
#define VERSION  "RBTree shared library version 3.1"

const char * rbtree_author  = AUTHOR;
const char * rbtree_version = VERSION;

/*
  Container Of Red Black Trees
  (C) 2011 Hong Yuan
 */

inline
static const void * default_getkey (const void * pdata ) 
{ 
	return pdata; 
}

inline
struct rb_node_data* get_node_entry(void *data_field)
{
 	return rb_entry(data_field, struct rb_node_data, data); 
}

inline
int get_node_data_size(void *data_field)
{
	return get_node_entry(data_field)->size;
}

inline
void * get_data_pointer(struct rb_node_data *rnd)
{
	return rnd->data;
}

inline
int get_data_size(struct rb_node_data *rnd)
{
	return rnd->size;
}

inline
static void * cmp_init_error()
{
	printf("Error: No define callback function no defined of comparison.\n");
	printf("       Must define and write it\n");
	printf("       Generic container version 3.0\n");
	abort();
	return (void*)0;
}

/*
 * Initializing rbtree root
 */
inline
void rbt_init(struct rb_root *root, getkey_func_t * getkey, cmp_func_t *cmp)
{
	*root = RB_ROOT;
	//assert(cmp != 0);  // cmp not is null to pass
	//root->cmp = cmp;
	root->cmp =    ( 0 == cmp    ? cmp_init_error() : cmp );
	root->getkey = ( 0 == getkey ? default_getkey   : getkey );
}

/*
 * stack alloc rbtree node-data
 */
struct rb_node_data *rbt_node_new(size_t size)
{
	struct rb_node_data *node = 
		calloc(1, sizeof(struct rb_node_data) + size);
	if (node) 
		node->size = size;
	return node;
}

/*
 * free rbtree node-data
 */
void rbt_node_free(struct rb_node_data *node)
{
	if (node)
		free(node);
}

/*
 * Search key node from rbtree
 *   Never attempt to modify the key value content 
 *   This will destroy the structure of the Red-Black tree 
 *   You must copy a object processing 
 */
inline
struct rb_node_data *rbt_search(struct rb_root *root, const void* key)
{
	struct rb_node *node = root->rb_node;
	
	while (node) 
	{
		struct rb_node_data *this = 
			rb_entry(node, struct rb_node_data, rb_node);
		
		int result = root->cmp(key, root->getkey(this->data));

		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else
			return this;
	}
	return 0;
}

/*
 * Insert node into rbtree
 */
inline
int rbt_insert(struct rb_root *root, struct rb_node_data *new_node)
{
	struct rb_node **now = &(root->rb_node); 
	struct rb_node  *parent = 0;
		
	/* Figure out where to put now node */
	while (*now) 
	{
		struct rb_node_data *this = 
			rb_entry(*now, struct rb_node_data, rb_node);

		int result = 
			root->cmp(root->getkey(new_node->data) 
					, root->getkey(this->data));
		
		parent = *now;
		
		if (result < 0)
			now = &((*now)->rb_left);
		else if (result > 0)
			now = &((*now)->rb_right);
		else
			return -1; // the key is already exists
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&(new_node->rb_node), parent, now);
	rb_insert_color(&(new_node->rb_node), root);

	return 0;
}


/*
 * Delete the key node from rbtree
 *     delete node from rbtree, return deleted node pointer
 */
inline
struct rb_node_data *rbt_delete(struct rb_root *root, const void *key)
{
	struct rb_node_data *find = rbt_search(root, key);
	if (!find)
		return 0;
	rb_erase(&find->rb_node, root);
	return find;
}

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
 */
inline
void rbt_erase(struct rb_root *root, struct rb_node_data *node)
{
	rb_erase(&node->rb_node, root);
}

/*
 * Replace the key node from rbtree for new rb_node_data
 *    replace node from rbtree, return old node pointer
 */
inline
struct rb_node_data * rbt_replace(struct rb_root *root, 
		struct rb_node_data *current_node)
{
	struct rb_node_data *old_node = 
		rbt_search(root, root->getkey(current_node->data));
	if (!old_node)
		return 0;
	rb_replace_node(&(old_node->rb_node), 
			&current_node->rb_node, root);
	return old_node;
}

/*
 * Traversal of the node processing
 */
inline
static int default_action(void *pn, void *pe)
{
	return 1;
}

/*
 * node : leaf node
 * pndata : node data 
 * pedata : external data
 * action : callback function pointer
 * succ_ret : action successful count
 */
inline static 
int rbt_inorder_aider(struct rb_node *node, void* pndata, void *pedata,
		int (*action) (void *pndata, void *pedata), int *succ_ret)
{
	if (node == NULL)
		return 0;
	int count = rbt_inorder_aider(node->rb_left ,
			/* external data for callback */
		       	rb_entry(node->rb_left, 
				struct rb_node_data, rb_node)->data
			/* external data for callback */
			, pedata 
			, action, succ_ret);
	if (action(pndata, pedata) && succ_ret)
		++*succ_ret;
	++count;
	count += rbt_inorder_aider(node->rb_right , 
			/* only node data for callback */ 
			rb_entry(node->rb_right, 
				struct rb_node_data, rb_node)->data
			/* external data for callback */
			, pedata 
			, action, succ_ret);
	return count;
}

/* 
 * Inorder Traversing the Red-Black tree
 * root : rbtree root
 * pedata : external data
 * action : callback function pointer
 * action_succ_ret : action successful count
 *
 * return-int : node count
 */
inline
int rbt_inorder(struct rb_root *root, void *pedata,
		int (*action) (void *pndata, void *pedata), int *action_succ_ret)
{
	if (action == NULL)
		action = default_action; // true
	if (root == NULL)
		return 0;
	if (action_succ_ret)
		*action_succ_ret = 0;
	return rbt_inorder_aider(root->rb_node 
			/* only node data for callback */ 
			, rb_entry(root->rb_node, 
				struct rb_node_data, rb_node)->data 
			// external data for callback
			, pedata 
			, action, action_succ_ret);
}

static inline
int rbt_clear_aider(struct rb_node *node, void* pndata, void *pedata,
		int (*action) (void *pndata, void *pedata), int *succ_ret)
{
	if (node == NULL)
		return 0;
	int count = rbt_clear_aider(node->rb_left
			, rb_entry(node->rb_left, 
				struct rb_node_data, rb_node)->data
			, pedata
			, action, succ_ret);
	count += rbt_clear_aider(node->rb_right 
			, rb_entry(node->rb_right, 
				struct rb_node_data, rb_node)->data
			, pedata
			, action, succ_ret);
	if (action(pndata, pedata) && succ_ret)
		(*succ_ret) ++;
	++count;
	//void *p = rb_entry(node, struct rb_node_data, rb_node);
	free(rb_entry(node, struct rb_node_data, rb_node));
	//printf("free %p\n", p);
	return count;
}

/*
 * clear the rbtree
 */
inline
int rbt_clear(struct rb_root *root, void *pedata, 
	int (*action)(void *pndata, void *pedata), int *action_succ_ret)
{

	if (action == NULL)
		action = default_action; // return true
	if (root == NULL)
		return 0;
	int count;
	if (action_succ_ret != 0)
		*action_succ_ret = 0;
	count =  rbt_clear_aider(root->rb_node 
			, rb_entry(root->rb_node, 
				struct rb_node_data, rb_node)->data 
			, pedata
			, action, action_succ_ret);
	root->rb_node = NULL;
	return count; /* the clear node count */
}

/*
 * first node [Leftmost node]
 */
inline
struct rb_node_data * rbt_node_first(struct rb_root *root)
{
	struct rb_node * node = rb_first(root);
	if (node == NULL)
		return NULL;
	return rb_entry(node, struct rb_node_data, rb_node);
}

/*
 * first data of node
 */
inline
void * rbt_data_first(struct rb_root *root)
{
	struct rb_node_data *node_data;
	node_data = rbt_node_first(root);
	if (node_data == NULL)
		return NULL;
	return node_data->data;
}

/*
 * last node [Rightmost node]
 */
inline
struct rb_node_data * rbt_node_last(struct rb_root *root)
{
	struct rb_node * node = rb_last(root);
	if (node == NULL)
		return NULL;
	return rb_entry(node, struct rb_node_data, rb_node);
}

/*
 * last data of node
 */
inline
void * rbt_data_last(struct rb_root *root)
{
	struct rb_node_data *node_data;
	node_data = rbt_node_last(root);
	if (node_data == NULL)
		return NULL;
	return node_data->data;
}

/*
 * next node
 */
inline
struct rb_node_data *rbt_node_next(struct rb_node_data *data_node)
{
	struct rb_node* node;
	node = rb_next(&data_node->rb_node);
	if (node == NULL)
		return NULL;
	return rb_entry(node, struct rb_node_data, rb_node);

}	

/*
 * next data of node
 */
inline
void *rbt_data_next(struct rb_node_data *data_node)
{
	struct rb_node_data* rnd;
	rnd = rbt_node_next(data_node);
	if (rnd == NULL)
		return NULL;
	return rnd->data;
}

/*
 * prev data of node
 */
inline
struct rb_node_data *rbt_node_prev(struct rb_node_data *data_node)
{
	struct rb_node* node;
	node = rb_prev(&data_node->rb_node);
	if (node == NULL)
		return NULL;
	return rb_entry(node, struct rb_node_data, rb_node);
}	

/*
 * prev data of node
 */
inline
void *rbt_data_prev(struct rb_node_data *data_node)
{
	struct rb_node_data* rnd;
	rnd = rbt_node_prev(data_node);
	if (rnd == NULL)
		return NULL;
	return rnd->data;
}	

// rbtree.c source codes
// rbtree.c
// {{{
// rbtree.c

/*
  Red Black Trees
  (C) 1999  Andrea Arcangeli <andrea@suse.de>
  (C) 2002  David Woodhouse <dwmw2@infradead.org>
  
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

  linux/lib/rbtree.c
*/

//#include "rbtree.h" 

static void __rb_rotate_left(struct rb_node *node, struct rb_root *root)
{
	struct rb_node *right = node->rb_right;
	struct rb_node *parent = rb_parent(node);

	if ((node->rb_right = right->rb_left))
		rb_set_parent(right->rb_left, node);
	right->rb_left = node;

	rb_set_parent(right, parent);

	if (parent)
	{
		if (node == parent->rb_left)
			parent->rb_left = right;
		else
			parent->rb_right = right;
	}
	else
		root->rb_node = right;
	rb_set_parent(node, right);
}

static void __rb_rotate_right(struct rb_node *node, struct rb_root *root)
{
	struct rb_node *left = node->rb_left;
	struct rb_node *parent = rb_parent(node);

	if ((node->rb_left = left->rb_right))
		rb_set_parent(left->rb_right, node);
	left->rb_right = node;

	rb_set_parent(left, parent);

	if (parent)
	{
		if (node == parent->rb_right)
			parent->rb_right = left;
		else
			parent->rb_left = left;
	}
	else
		root->rb_node = left;
	rb_set_parent(node, left);
}

void rb_insert_color(struct rb_node *node, struct rb_root *root)
{
	struct rb_node *parent, *gparent;

	while ((parent = rb_parent(node)) && rb_is_red(parent))
	{
		gparent = rb_parent(parent);

		if (parent == gparent->rb_left)
		{
			{
				register struct rb_node *uncle = gparent->rb_right;
				if (uncle && rb_is_red(uncle))
				{
					rb_set_black(uncle);
					rb_set_black(parent);
					rb_set_red(gparent);
					node = gparent;
					continue;
				}
			}

			if (parent->rb_right == node)
			{
				register struct rb_node *tmp;
				__rb_rotate_left(parent, root);
				tmp = parent;
				parent = node;
				node = tmp;
			}

			rb_set_black(parent);
			rb_set_red(gparent);
			__rb_rotate_right(gparent, root);
		} else {
			{
				register struct rb_node *uncle = gparent->rb_left;
				if (uncle && rb_is_red(uncle))
				{
					rb_set_black(uncle);
					rb_set_black(parent);
					rb_set_red(gparent);
					node = gparent;
					continue;
				}
			}

			if (parent->rb_left == node)
			{
				register struct rb_node *tmp;
				__rb_rotate_right(parent, root);
				tmp = parent;
				parent = node;
				node = tmp;
			}

			rb_set_black(parent);
			rb_set_red(gparent);
			__rb_rotate_left(gparent, root);
		}
	}

	rb_set_black(root->rb_node);
}
//EXPORT_SYMBOL(rb_insert_color);

static void __rb_erase_color(struct rb_node *node, struct rb_node *parent,
			     struct rb_root *root)
{
	struct rb_node *other;

	while ((!node || rb_is_black(node)) && node != root->rb_node)
	{
		if (parent->rb_left == node)
		{
			other = parent->rb_right;
			if (rb_is_red(other))
			{
				rb_set_black(other);
				rb_set_red(parent);
				__rb_rotate_left(parent, root);
				other = parent->rb_right;
			}
			if ((!other->rb_left || rb_is_black(other->rb_left)) &&
			    (!other->rb_right || rb_is_black(other->rb_right)))
			{
				rb_set_red(other);
				node = parent;
				parent = rb_parent(node);
			}
			else
			{
				if (!other->rb_right || rb_is_black(other->rb_right))
				{
					rb_set_black(other->rb_left);
					rb_set_red(other);
					__rb_rotate_right(other, root);
					other = parent->rb_right;
				}
				rb_set_color(other, rb_color(parent));
				rb_set_black(parent);
				rb_set_black(other->rb_right);
				__rb_rotate_left(parent, root);
				node = root->rb_node;
				break;
			}
		}
		else
		{
			other = parent->rb_left;
			if (rb_is_red(other))
			{
				rb_set_black(other);
				rb_set_red(parent);
				__rb_rotate_right(parent, root);
				other = parent->rb_left;
			}
			if ((!other->rb_left || rb_is_black(other->rb_left)) &&
			    (!other->rb_right || rb_is_black(other->rb_right)))
			{
				rb_set_red(other);
				node = parent;
				parent = rb_parent(node);
			}
			else
			{
				if (!other->rb_left || rb_is_black(other->rb_left))
				{
					rb_set_black(other->rb_right);
					rb_set_red(other);
					__rb_rotate_left(other, root);
					other = parent->rb_left;
				}
				rb_set_color(other, rb_color(parent));
				rb_set_black(parent);
				rb_set_black(other->rb_left);
				__rb_rotate_right(parent, root);
				node = root->rb_node;
				break;
			}
		}
	}
	if (node)
		rb_set_black(node);
}

void rb_erase(struct rb_node *node, struct rb_root *root)
{
	struct rb_node *child, *parent;
	int color;

	if (!node->rb_left)
		child = node->rb_right;
	else if (!node->rb_right)
		child = node->rb_left;
	else
	{
		struct rb_node *old = node, *left;

		node = node->rb_right;
		while ((left = node->rb_left) != NULL)
			node = left;

		if (rb_parent(old)) {
			if (rb_parent(old)->rb_left == old)
				rb_parent(old)->rb_left = node;
			else
				rb_parent(old)->rb_right = node;
		} else
			root->rb_node = node;

		child = node->rb_right;
		parent = rb_parent(node);
		color = rb_color(node);

		if (parent == old) {
			parent = node;
		} else {
			if (child)
				rb_set_parent(child, parent);
			parent->rb_left = child;

			node->rb_right = old->rb_right;
			rb_set_parent(old->rb_right, node);
		}

		node->rb_parent_color = old->rb_parent_color;
		node->rb_left = old->rb_left;
		rb_set_parent(old->rb_left, node);

		goto color;
	}

	parent = rb_parent(node);
	color = rb_color(node);

	if (child)
		rb_set_parent(child, parent);
	if (parent)
	{
		if (parent->rb_left == node)
			parent->rb_left = child;
		else
			parent->rb_right = child;
	}
	else
		root->rb_node = child;

 color:
	if (color == RB_BLACK)
		__rb_erase_color(child, parent, root);
}
//EXPORT_SYMBOL(rb_erase);

static void rb_augment_path(struct rb_node *node, rb_augment_f func, void *data)
{
	struct rb_node *parent;

up:
	func(node, data);
	parent = rb_parent(node);
	if (!parent)
		return;

	if (node == parent->rb_left && parent->rb_right)
		func(parent->rb_right, data);
	else if (parent->rb_left)
		func(parent->rb_left, data);

	node = parent;
	goto up;
}

/*
 * after inserting @node into the tree, update the tree to account for
 * both the new entry and any damage done by rebalance
 */
void rb_augment_insert(struct rb_node *node, rb_augment_f func, void *data)
{
	if (node->rb_left)
		node = node->rb_left;
	else if (node->rb_right)
		node = node->rb_right;

	rb_augment_path(node, func, data);
}

/*
 * before removing the node, find the deepest node on the rebalance path
 * that will still be there after @node gets removed
 */
struct rb_node *rb_augment_erase_begin(struct rb_node *node)
{
	struct rb_node *deepest;

	if (!node->rb_right && !node->rb_left)
		deepest = rb_parent(node);
	else if (!node->rb_right)
		deepest = node->rb_left;
	else if (!node->rb_left)
		deepest = node->rb_right;
	else {
		deepest = rb_next(node);
		if (deepest->rb_right)
			deepest = deepest->rb_right;
		else if (rb_parent(deepest) != node)
			deepest = rb_parent(deepest);
	}

	return deepest;
}

/*
 * after removal, update the tree to account for the removed entry
 * and any rebalance damage.
 */
void rb_augment_erase_end(struct rb_node *node, rb_augment_f func, void *data)
{
	if (node)
		rb_augment_path(node, func, data);
}

/*
 * This function returns the first node (in sort order) of the tree.
 */
struct rb_node *rb_first(const struct rb_root *root)
{
	struct rb_node	*n;

	n = root->rb_node;
	if (!n)
		return NULL;
	while (n->rb_left)
		n = n->rb_left;
	return n;
}
//EXPORT_SYMBOL(rb_first);

struct rb_node *rb_last(const struct rb_root *root)
{
	struct rb_node	*n;

	n = root->rb_node;
	if (!n)
		return NULL;
	while (n->rb_right)
		n = n->rb_right;
	return n;
}
//EXPORT_SYMBOL(rb_last);

struct rb_node *rb_next(const struct rb_node *node)
{
	struct rb_node *parent;

	if (rb_parent(node) == node)
		return NULL;

	/* If we have a right-hand child, go down and then left as far
	   as we can. */
	if (node->rb_right) {
		node = node->rb_right; 
		while (node->rb_left)
			node=node->rb_left;
		return (struct rb_node *)node;
	}

	/* No right-hand children.  Everything down and left is
	   smaller than us, so any 'next' node must be in the general
	   direction of our parent. Go up the tree; any time the
	   ancestor is a right-hand child of its parent, keep going
	   up. First time it's a left-hand child of its parent, said
	   parent is our 'next' node. */
	while ((parent = rb_parent(node)) && node == parent->rb_right)
		node = parent;

	return parent;
}
//EXPORT_SYMBOL(rb_next);

struct rb_node *rb_prev(const struct rb_node *node)
{
	struct rb_node *parent;

	if (rb_parent(node) == node)
		return NULL;

	/* If we have a left-hand child, go down and then right as far
	   as we can. */
	if (node->rb_left) {
		node = node->rb_left; 
		while (node->rb_right)
			node=node->rb_right;
		return (struct rb_node *)node;
	}

	/* No left-hand children. Go up till we find an ancestor which
	   is a right-hand child of its parent */
	while ((parent = rb_parent(node)) && node == parent->rb_left)
		node = parent;

	return parent;
}
//EXPORT_SYMBOL(rb_prev);

void rb_replace_node(struct rb_node *victim, struct rb_node *new,
		     struct rb_root *root)
{
	struct rb_node *parent = rb_parent(victim);

	/* Set the surrounding nodes to point to the replacement */
	if (parent) {
		if (victim == parent->rb_left)
			parent->rb_left = new;
		else
			parent->rb_right = new;
	} else {
		root->rb_node = new;
	}
	if (victim->rb_left)
		rb_set_parent(victim->rb_left, new);
	if (victim->rb_right)
		rb_set_parent(victim->rb_right, new);

	/* Copy the pointers/colour from the victim to the replacement */
	*new = *victim;
}
//EXPORT_SYMBOL(rb_replace_node);

// rbtree.c
// }}}
// rbtree.c
// rbtree.c source codes
