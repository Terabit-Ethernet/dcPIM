#ifndef PRIORITY_QUEUE_H
#define PRIORITY_QUEUE_H

#include <stdio.h> 
#include <stdlib.h> 
#include <rte_rwlock.h>
typedef struct node { 
    void* data; 
    // Lower values indicate higher priority 
    uint32_t priority; 
  
    struct node* next; 
  
} Node; 

typedef struct priorityq {
	Node* head;
	bool (*comp)(const void*, const void*);
	rte_rwlock_t rw_lock;

} Pq;


int pq_isEmpty(Pq* pq);
Node* pq_newNode(void* d);
void pq_init(Pq* pq, bool(*comp)(const void*, const void*));
void* pq_peek(Pq* pq);
void pq_pop(Pq* pq);
void pq_push(Pq* pq, void* d); 
#endif