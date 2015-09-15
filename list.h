#ifndef __YH_LIST_H__
#define __YH_LIST_H__

#ifdef __cplusplus
extern "C"
{
#endif

/**********************************************************
功能: 计算MEMBER成员在TYPE结构体中的偏移量
**********************************************************/
#ifndef offsetof
#define offsetof(type, member) \
    (size_t)&(((type *)0)->member)
#endif

/**********************************************************
功能: 计算链表元素的起始地址
输入:
    ptr：    type结构体中的链表指针
    type:   结构体类型
    member: 链表成员名称
**********************************************************/
//#define container_of(ptr, type, member) (type *)((char*)(ptr) - offsetof(type, member))
#ifndef container_of
#define container_of(ptr, type, member)  \
    ({\
     const typeof(((type *)0)->member) * __mptr = (ptr);\
     (type *)((char *)__mptr - offsetof(type, member)); \
     })
#endif

#ifndef struct_entry
#define struct_entry(ptr, type,  member) container_of(ptr, type, member)
#endif

#define LIST_HEAD_INIT(name)    {&(name), &(name)}

struct list
{
    struct list *prev, *next;
};

static inline void list_init(struct list *list)
{
    list->next = list;
    list->prev = list;
}

static inline int list_empty(struct list *list)
{
    return list->next == list;
}

static inline void list_insert_prev(struct list* link, struct list *newn)
{
    newn->prev = link->prev;
    newn->next = newn;
    newn->prev->next = link;
    newn->next->prev = link;
}
static inline void list_insert_next(struct list* link, struct list *newn)
{
    newn->next = link->next;
    newn->prev = link;
    newn->next->prev = newn;
    newn->prev->next = newn;
}

/**********************************************************
  功能: 将new_link节点插入到list链表中
  表头作为哨兵 插入表头之后第一个位置
 **********************************************************/
static inline void list_insert(struct list *link, struct list *new_link)
{
    new_link->prev       = link->prev;
    new_link->next       = link;
    new_link->prev->next = new_link;
    new_link->next->prev = new_link;
}

/**********************************************************
  功能: 将new_link节点追加到list链表中
  对于循环列表而言插入到表头之前即是添加到表尾
 **********************************************************/
static inline void list_append(struct list *list, struct list *new_link)
{
    list_insert(list->prev, new_link);
}

/**********************************************************
  功能: 从链表中移除节点
 **********************************************************/
static inline void list_remove(struct list *link)
{
    link->prev->next = link->next;
    link->next->prev = link->prev;
}

/**********************************************************
获取link节点对应的结构体变量地址
link:   链表节点指针
type:   结构体类型名
member: 结构体成员变量名
**********************************************************/
#define list_entry(link, type, member)  container_of(link, type, member)


/**********************************************************
获取链表头节点对应的结构体变量地址
list:   链表头指针
type:   结构体类型名
member: 结构体成员变量名
Note:
链表头节点实际为链表头的下一个节点,链表头未使用，相当于哨兵
**********************************************************/
#define list_head(list, type, member) list_entry((list)->next, type, member)

/**********************************************************
获取链表尾节点对应的结构体变量地址
list:   链表头指针
type:   结构体类型名
member: 结构体成员变量名
**********************************************************/
#define list_tail(list, type, member) list_entry((list)->prev, type, member)

/**********************************************************
返回链表下一个节点对应的结构体指针
elm:    结构体变量指针
type:   结构体类型名
member: 结构体成员变量名(链表变量名)
**********************************************************/
#define list_next(elm,type,member) list_entry((elm)->member.next, type, member)

/* 返回上一个 */
#define list_prev(elm,type,member) list_entry((elm)->member.prev, type, member)

/**********************************************************
遍历链表所有节点对应的结构体
pos : 结构体指针
type : 结构体类型名
list : 链表头指针
member : 结构体成员变量名(链表变量名)
Note : 链表头未使用，因此遍历结束后，pos指向的不是有效的结构体地址
**********************************************************/
#define list_for_each_entry(pos, type, list, member)    \
for (pos = list_head(list, type, member);               \
    &pos->member != (list);                              \
    pos = list_next(pos, type, member))

#define list_for_each_entry_reverse(pos, type, list, member)    \
for (pos = list_tail(list, type, member);               \
    &pos->member != (list);                              \
    pos = list_prev(pos, type, member))

//////////// 手工遍历
/*
#include <stdio.h>
   struct list ls = LIST_HEAD_INIT(ls);
   //.... list_appent(...);

    struct list *p1, *p2;
    p2 = &ls;
    p1 = p2->next;
    printf("\nend %12lx, tail %12lx first %12lx, new %12lx\n", p2, p2->prev, p1, &pc->node);
    for (;p1 != p2; p1 = p1->next) {
        printf("\tpc %12lx [%12lx %12lx]\n", p1, p1->prev, p1->next);
    }
*/
///////////

#ifdef __cplusplus
}
#endif
#endif /* __YH_LIST_H__ */
