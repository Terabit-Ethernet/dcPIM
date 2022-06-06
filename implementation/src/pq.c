// C code to implement Priority Queue 
// using Linked List   
#include <rte_malloc.h>  
#include <stdbool.h>
#include "pq.h"
// Node 
  
// Function to Create A New Node 
Node* pq_newNode(void* d) 
{ 
    Node* temp = (Node*)rte_zmalloc("", sizeof(Node), 0); 
    temp->data = d; 
    temp->next = NULL; 
  
    return temp; 
} 

void pq_init(Pq* pq, bool(*comp)(const void*, const void*)) {
    pq->head = NULL;
    pq->comp = comp;
    rte_rwlock_init(&pq->rw_lock);
}

int pq_isEmpty(Pq* pq) 
{ 
    rte_rwlock_read_lock (&pq->rw_lock);
    int empty = (pq->head) == NULL;
    rte_rwlock_read_unlock(&pq->rw_lock);
    return empty; 
} 

// Return the value at head 
void* pq_peek(Pq* pq) 
{ 
    rte_rwlock_read_lock (&pq->rw_lock);

    void* data  =  NULL;
    if(pq->head == NULL) 
        data = NULL;
    else 
        data = pq->head->data;
    rte_rwlock_read_unlock(&pq->rw_lock);

    return data; 
} 
  
// Removes the element with the 
// highest priority form the list 
void pq_pop(Pq* pq) 
{ 
    rte_rwlock_write_lock (&pq->rw_lock);
    if(pq->head == NULL) {
        rte_rwlock_write_unlock (&pq->rw_lock);
        return;
    }
    Node* temp = pq->head; 
    (pq->head) = (pq->head)->next;
    rte_free(temp); 
    rte_rwlock_write_unlock (&pq->rw_lock);

} 
  
// Function to push according to priority 
void pq_push(Pq* pq, void* d) 
{ 
    rte_rwlock_write_lock (&pq->rw_lock);

    Node* start = pq->head; 
  
    // Create new Node 
    Node* temp = pq_newNode(d); 
    // Special Case: The head of list has lesser 
    // priority than new node. So insert new 
    // node before head node and change head node. 
    if (pq->head == NULL || pq->comp(pq->head->data, d)) { 
  
        // Insert New Node before head 
        temp->next = pq->head; 
        pq->head = temp; 
    } 
    else { 
  
        // Traverse the list and find a 
        // position to insert new node 
        while (start->next != NULL && 
               pq->comp(d, start->next->data)) { 
            start = start->next; 
        } 
  
        // Either at the ends of the list 
        // or at required position 
        temp->next = start->next; 
        start->next = temp; 
    } 
    rte_rwlock_write_unlock (&pq->rw_lock);

}