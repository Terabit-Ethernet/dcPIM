// #define DEBUG
#include <linux/dmaengine.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/dma-mapping.h>
#include "dcpim_ioat.h"
#include "net_dcpim.h"
#include "linux_dcpim.h"

struct list_head ioat_device_list = LIST_HEAD_INIT(ioat_device_list);
u32 num_ioat_devices;
DEFINE_SPINLOCK(device_spinlock);

int init_ioat_dma_devices(void) {
    dma_cap_mask_t mask;
    struct dma_chan *chan = NULL;
    dma_cap_zero(mask);
    dma_cap_set(DMA_MEMCPY, mask);

    chan = dma_request_chan_by_mask(&mask);
    while (!IS_ERR(chan)) {
        struct ioat_dma_device *dma_device = kzalloc(sizeof(struct ioat_dma_device), GFP_KERNEL);
        dma_device->owner = 0;
        dma_device->device_id = num_ioat_devices;
        dma_device->chan = chan;
        INIT_LIST_HEAD(&dma_device->comp_list);
        spin_lock_init(&dma_device->comp_list_lock);

        list_add_tail(&dma_device->list, &ioat_device_list);

        num_ioat_devices++;
        printk("Found DMA device: %s\n", dev_name(chan->device->dev));

        chan = dma_request_chan_by_mask(&mask);
    }
    return 0;
}

// struct ioat_dma_device *find_ioat_dma_device(u64 device_id) {
//   struct ioat_dma_device *dma_device;
//   list_for_each_entry(dma_device, &dma_devices, list) {
//     if (dma_device->device_id == device_id && dma_device->owner == current->tgid) {
//       return dma_device;
//     }
//   }
//   return NULL;
// }

struct ioat_dma_device *get_free_ioat_dma_device(void *owner) {
    struct ioat_dma_device *dma_device;
    unsigned long flags;
    spin_lock_irqsave(&device_spinlock, flags);
    list_for_each_entry(dma_device, &ioat_device_list, list) {
        if (dma_device->owner == 0) {
            dma_device->owner = owner;
            spin_unlock_irqrestore(&device_spinlock, flags);
            return dma_device;
        }
    }
    spin_unlock_irqrestore(&device_spinlock, flags);
    return NULL;
}

void return_ioat_dma_device(struct ioat_dma_device *dma_device) {
    unsigned long flags;
    spin_lock_irqsave(&device_spinlock, flags);
    dma_device->owner = 0;
    spin_unlock_irqrestore(&device_spinlock, flags);
}

// struct ioat_dma_device *get_available_ioat_dma_device(void) {
//   unsigned long flags;
//   struct ioat_dma_device *dma_device;

//   spin_lock_irqsave(&device_spinlock, flags);
//   list_for_each_entry(dma_device, &dma_devices, list) {
//     if (dma_device->owner > 0) {
//       continue;
//     }

//     dev_info(dev, "%s: using device %s by %d\n", __func__,
//              dev_name(dma_device->chan->device->dev), current->tgid);
//     dma_device->owner = current->tgid;
//     break;
//   }
//   spin_unlock_irqrestore(&device_spinlock, flags);

//   if (dma_device == NULL) dma_device = ERR_PTR(-ENODEV);
//   return dma_device;
// }

void release_ioat_dma_device(struct ioat_dma_device *dma_device) {
    struct ioat_dma_desc *comp_entry, *comp_tmp;
    unsigned long flags;
    dmaengine_terminate_sync(dma_device->chan);
    dma_release_channel(dma_device->chan);
    spin_lock_irqsave(&device_spinlock, flags);
    list_for_each_entry_safe(comp_entry, comp_tmp, &dma_device->comp_list, list) {
        list_del(&comp_entry->list);
        kfree(comp_entry);
    }
    dma_device->owner = 0;
    spin_unlock_irqrestore(&device_spinlock, flags);
}

void release_ioat_dma_devices(void) {
    struct ioat_dma_device *dma_device;
    list_for_each_entry(dma_device, &ioat_device_list, list) {
        release_ioat_dma_device(dma_device);
    }
}

static void ioat_dma_sync_callback(void *param) {
    struct ioat_dma_desc *comp_entry = param;
    struct ioat_dma_device *dma_device = comp_entry->req->device;
    // spin_lock(&dma_device->comp_list_lock);
    // list_del(&comp_entry->list);
    // spin_unlock(&dma_device->comp_list_lock);
    dma_unmap_page(dma_device->chan->device->dev, comp_entry->src, comp_entry->size, DMA_BIDIRECTIONAL);
    dma_unmap_page(dma_device->chan->device->dev, comp_entry->dst, comp_entry->size, DMA_BIDIRECTIONAL);
    /* To Do: add entry back to socket's list */
    if(refcount_dec_and_test(&comp_entry->req->refcnt)) {
        // printk("start add\n");
        llist_add(&comp_entry->req->lentry, &dcpim_sk(comp_entry->req->sk)->receiver.clean_req_list);
        // printk("finish add\n");
    }
    complete(&comp_entry->finished);
}

int ioat_dma_ioctl_dma_submit(struct page* from_page, unsigned int from_offset,
                              struct page* to_page, unsigned int to_offset, size_t len,
                              struct dcpim_dcopy_request *req) {
    enum dma_ctrl_flags flags = DMA_CTRL_ACK | DMA_PREP_INTERRUPT;
    dma_addr_t src, dst;
    struct dma_async_tx_descriptor *chan_desc;
    struct ioat_dma_desc *comp_entry;
    struct ioat_dma_device *dma_device = req->device;
    unsigned long lock_flags;
    src = dma_map_page(dma_device->chan->device->dev, from_page, from_offset, len, DMA_TO_DEVICE);
    dst = dma_map_page(dma_device->chan->device->dev, to_page, to_offset, len, DMA_FROM_DEVICE);
    // dev_dbg(dev, "%s: DMA about to be initialized: 0x%llx -> 0x%llx (size: 0x%llx bytes)\n",
    //         __func__, src, dst, len);

    chan_desc = dmaengine_prep_dma_memcpy(dma_device->chan, dst, src, len, flags);
    if (chan_desc == NULL) {
        dma_unmap_page(dma_device->chan->device->dev, src, len, DMA_BIDIRECTIONAL);
        dma_unmap_page(dma_device->chan->device->dev, dst, len, DMA_BIDIRECTIONAL);
        WARN_ON_ONCE(len == 0);
        printk("create descriptor fails: %u %u %lu\n", from_offset, to_offset, len);
        /* To Do: switch to the normal data copy data path in case it fails */
        return -EINVAL;
    } 
    comp_entry = kzalloc(sizeof(struct ioat_dma_desc), GFP_ATOMIC);
    init_completion(&comp_entry->finished);
    chan_desc->callback = ioat_dma_sync_callback;
    chan_desc->callback_param = comp_entry;
    comp_entry->src = src;
    comp_entry->dst = dst;
    comp_entry->size = len;
    comp_entry->req = req;
    refcount_inc(&req->refcnt);
    /* no need to incrment refcnt of sk, because recvmsg will wait until data copy is being finished */
    // /* only the last IO has skb pointer; for now, pages belonged to the same skb will send to the same DMA device */
    // comp_entry->skb = skb;
    /* dma_device is valid as the device will be released only after all DMA oprations have been finished */
    comp_entry->cookie = dmaengine_submit(chan_desc);
	if (dma_submit_error(comp_entry->cookie)) {
        dma_unmap_page(dma_device->chan->device->dev, src, len, DMA_BIDIRECTIONAL);
        dma_unmap_page(dma_device->chan->device->dev, dst, len, DMA_BIDIRECTIONAL);
		printk("Failed to do DMA tx_submit\n");
        return -EINVAL;
	}

    spin_lock_irqsave(&dma_device->comp_list_lock, lock_flags);
    list_add_tail(&comp_entry->list, &dma_device->comp_list);
    dma_device->num_reqs++;
    spin_unlock_irqrestore(&dma_device->comp_list_lock, lock_flags);
    // dma_async_issue_pending(req->device->chan);
    // wait_for_completion(&comp_entry->finished);
    return 0;
}

void ioat_dma_skb_iter(const struct sk_buff *skb, int offset,
			       struct iov_iter *to, int len, struct dcpim_dcopy_request *req)
{
	int start = skb_headlen(skb);
	int i, copy = start - offset;
    int act_copy;
	struct sk_buff *frag_iter;

	/* Copy header. */
	if (copy > 0) {
		if (copy > len)
			copy = len;
        while(copy > 0)  {
            int poffset = (unsigned long)(skb->data + offset) & (PAGE_SIZE - 1);
            int to_offset = (to->iov_offset + to->bvec->bv_offset) & (PAGE_SIZE - 1);
            struct page* page = virt_to_page(skb->data + offset);
            struct page* to_page = to->bvec->bv_page + (to->iov_offset + to->bvec->bv_offset) / PAGE_SIZE;
            act_copy = min_t(int, PAGE_SIZE - poffset, copy);
            act_copy = min_t(int, min_t(int, PAGE_SIZE - to_offset, to->bvec->bv_len - to->iov_offset), act_copy);
            // if(act_copy == 0)
            //     printk("copy linear part: %ld %ld %ld\n", PAGE_SIZE - poffset,  PAGE_SIZE - to_offset, to->bvec->bv_len - to->iov_offset);
            ioat_dma_ioctl_dma_submit(page, poffset, to_page, to_offset, act_copy, req);
            iov_iter_advance(to, act_copy);
            offset += act_copy;
            len -= act_copy;
            copy -= act_copy;
        }
		if (len == 0)
			return;
	}

	/* Copy paged appendix. Hmm... why does this look so complicated? */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		int end;
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		WARN_ON(start > offset + len);

		end = start + skb_frag_size(frag);
		if ((copy = end - offset) > 0) {
			if (copy > len)
				copy = len;
            while (copy > 0) {
                /* need change this */
                int poffset =  (skb_frag_off(frag) + offset - start) & (PAGE_SIZE - 1);
                int to_offset = (to->iov_offset + to->bvec->bv_offset) & (PAGE_SIZE - 1);
                struct page* page = skb_frag_page(frag) + ((skb_frag_off(frag) + offset - start) >> PAGE_SHIFT);
                struct page* to_page = to->bvec->bv_page + (to->iov_offset + to->bvec->bv_offset) / PAGE_SIZE;
                act_copy = min_t(int, PAGE_SIZE - poffset, copy);
                act_copy = min_t(int, min_t(int, PAGE_SIZE - to_offset, to->bvec->bv_len - to->iov_offset), act_copy);
                WARN_ON_ONCE(skb_frag_size(frag) > PAGE_SIZE);
                // if(act_copy == 0) {
                //     printk("copy:%d copy nonlinear part: %ld %ld %ld %d %ld\n", copy,
                //      PAGE_SIZE - poffset,  PAGE_SIZE - to_offset, to->bvec->bv_len - to->iov_offset, to->bvec->bv_len, to->iov_offset);
                //     printk("nr_segs:%ld %p\n", to->nr_segs, req->skb);
                // }
                ioat_dma_ioctl_dma_submit(page, poffset, to_page, to_offset, act_copy, req);
                iov_iter_advance(to, act_copy);
                offset += act_copy;
                len -= act_copy;
                copy -= act_copy;
            }
			if (len == 0)
				return;
		}
		start = end;
	}

	skb_walk_frags(skb, frag_iter) {
		int end;

		WARN_ON(start > offset + len);

		end = start + frag_iter->len;
		if ((copy = end - offset) > 0) {
			if (copy > len)
				copy = len;
			ioat_dma_skb_iter(frag_iter, offset - start, to, copy, req);
            // iov_iter_advance(to, copy);
			if ((len -= copy) == 0)
				return;
			offset += copy;
		}
		start = end;
	}
	return;
}

int dcpim_dcopy_queue_request(struct dcpim_dcopy_request *req) {
    // printk("submit the request: %d %ld %p\n", req->len, req->iter.count, req->skb);
    int result = 0;
    ioat_dma_skb_iter(req->skb, req->offset, &req->iter, req->len, req);
    if(refcount_dec_and_test(&req->refcnt)) {
        /* the corner case */
        llist_add(&req->lentry, &dcpim_sk(req->sk)->receiver.clean_req_list);
    }    
    dma_async_issue_pending(req->device->chan);
    dcpim_dcopy_wait_all(req->device, &result);
    // dma_async_issue_pending(req->device->chan);
    // wait_for_completion();
    // printk("finish submit");
    return 0;
}



int dcpim_dcopy_wait_all (struct ioat_dma_device *dma_device, int *result) {
    struct ioat_dma_desc *comp, *tmp;
    // unsigned long flags;
    // unsigned long timeout;
    // enum dma_status status;
    int dma_result = 0;
    u64 num_completed = 0;
    // spin_lock_irqsave(&dma_device->comp_list_lock, flags);
    list_for_each_entry_safe(comp, tmp, &dma_device->comp_list, list) {
        if(dma_device->num_reqs <= 100)
            break;
        wait_for_completion(&comp->finished);
        dma_device->num_reqs--;
        // status = dma_async_is_tx_complete(dma_device->chan, comp->cookie, NULL, NULL);
        // dev_dbg(dev, "%s: wait completed.\n", __func__);

        // if (timeout == 0) {
        //     dev_warn(dev, "%s: DMA timed out!\n", __func__);
        //     dma_result = -ETIMEDOUT;
        // } else if (status != DMA_COMPLETE) {
        //     dev_warn(dev, "%s: DMA returned completion callback status of: %s\n",
        //     __func__, status == DMA_ERROR ? "error" : "in progress");
        //     dma_result = -EBUSY;
        // } else {
        //     dev_dbg(dev, "%s: DMA completed!\n", __func__);
        num_completed++;
        // }
        list_del(&comp->list);
        // dma_unmap_page(dma_device->chan->device->dev, comp->src, comp->size, DMA_BIDIRECTIONAL);
        // dma_unmap_page(dma_device->chan->device->dev, comp->dst, comp->size, DMA_BIDIRECTIONAL);
        kfree(comp);
        // if (dma_result != 0) {
        //     break;
        // }
        // kfree(comp_entry);

    }

    // spin_unlock_irqrestore(&dma_device->comp_list_lock, flags);
    *result = num_completed;
    return dma_result;
}
