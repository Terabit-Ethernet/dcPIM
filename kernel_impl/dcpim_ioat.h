#ifndef _DCPIM_IOAT_H_
#define _DCPIM_IOAT_H_

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/dax.h>
#include <linux/list.h>
#include <linux/dmaengine.h>
#include <linux/spinlock.h>


extern struct list_head ioat_device_list;
extern u32 num_ioat_devices;

enum dcpim_dcopy_state {
	DCPIM_DCOPY_SEND = 0,
	DCPIM_DCOPY_RECV,
	DCPIM_DCOPY_DONE,
};


struct dcpim_dcopy_response {
	struct llist_node	lentry;
	struct sk_buff *skb;
};

struct dcpim_dcopy_page {
	struct llist_node	lentry;
	struct bio_vec *bv_arr;
	struct sk_buff* skb;
	int max_segs;
};
struct ioat_dma_device {
	struct list_head list;
	u64 device_id;
	void* owner;
	struct dma_chan *chan;
	struct list_head comp_list;
	spinlock_t comp_list_lock;
	struct ioat_dma_device *device;
	int num_reqs;
};


struct dcpim_dcopy_request {
	enum dcpim_dcopy_state state;

	bool clean_skb;
	int io_cpu;
    struct sock *sk;
	struct sk_buff *skb;
	struct iov_iter iter;
	struct bio_vec *bv_arr;
	struct list_head	entry;
	struct llist_node	lentry;
	refcount_t refcnt;
	union{
		u32 offset;
		u32 seq;
	};
    int len;
	int remain_len;
	int max_segs;
	struct ioat_dma_device *device;
	// struct nd_dcopy_queue *queue;
};


/* DMA stuffs */
struct ioat_dma_desc {
	struct list_head list;
	// struct completion comp;
	dma_cookie_t cookie;
	dma_addr_t src;
	dma_addr_t dst;
	u64 size;
	struct dcpim_dcopy_request *req;
	struct completion finished; 
};


int init_ioat_dma_devices(void);
void release_ioat_dma_device(struct ioat_dma_device *dma_device);
void release_ioat_dma_devices(void);
struct ioat_dma_device *find_ioat_dma_device(u64 device_id);
void return_ioat_dma_device(struct ioat_dma_device *dma_device);
// struct ioat_dma_device *get_available_ioat_dma_device(void);
int ioat_dma_ioctl_dma_submit(struct page* from_page, unsigned int from_offset,
                              struct page* to_page, unsigned int to_offset, size_t len,
                              struct dcpim_dcopy_request *req);
struct ioat_dma_device *get_free_ioat_dma_device(void *owner);
int dcpim_dcopy_queue_request(struct dcpim_dcopy_request *req);
void ioat_dma_skb_iter(const struct sk_buff *skb, int offset,
			       struct iov_iter *to, int len, struct dcpim_dcopy_request *req);
int dcpim_dcopy_wait_all (struct ioat_dma_device *dma_device, int *result);				   
// int ioat_dma_ioctl_get_device_num(void __user *arg);
// int ioat_dma_ioctl_get_device(void __user *arg);
// int ioat_dma_ioctl_dma_wait_all(struct ioat_dma_device *dma_device, u64 *result);

/* device driver stuffs */
// extern struct device *dev;

#endif