#ifndef __KVM_VGPU_H__
#define __KVM_VGPU_H__

#include <linux/completion.h>
#include <linux/kvm_host.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/semaphore.h>
#include <linux/virtio_vsock.h>
#include <linux/hashtable.h>

#include <scea/kvm_policy.h>
#include <scea/common/devconf.h>
#include <scea/common/cmd_handler.h>
#include <scea/common/guest_mem.h>

typedef struct mem_region {
    uintptr_t base;
    uintptr_t offset;
    size_t size;
    struct mutex lock;
} KVM_VGPU_MemRegion;

// dummy struct reserved for memory swapping
struct obj_info {
    int dummy;
};

struct netlink_info {
    int vm_id;
    u32 worker_pid;
    u32 worker_port;

    struct list_head list;
    struct hlist_node node;
};

struct app_info {
    struct list_head list;

    int vm_id;
    u64 app_cid;
    u32 app_port;
    u32 worker_port;
    u32 worker_pid;
    size_t used_dev_mem;
    struct vm_info *vm_info;
    struct netlink_info *nl_info;
};

struct vm_info;

struct circ_send_queue;

struct vsock_info {
    struct vhost_vsock *vsock;
    int vm_id;
    struct vm_info *vm_info;

    /* Temporary send queue, polled by scheduler */
    struct circ_send_queue sq;

    /* VHOST_VSOCK helper functions */
    void (*vhost_signal_helper)(struct vsock_info *, struct pkt_wrapper *);
    void (*vhost_transport_helper)(struct virtio_vsock_pkt *);
};

struct vm_info
{
    int is_worker:           1;
    int is_manager:          1;
    int is_policy_installer: 1;
    int is_vm:               1;
    int is_reserved:         4;

    int vm_id;
    int guest_cid;
    struct vsock_info *vsock_info;
    struct app_info app_info_list;

    size_t used_dev_mem;
};

// TODO: rename as kvm_ava_dev
typedef struct kvm_vgpu_dev {
    size_t vm_count;
    int vm_ids[MAX_VM_NUM + 1];

    struct fasync_struct *async_queue;  /* asyn readers */

    //
    // Shared memory regions.
    //
    KVM_VGPU_MemRegion shm;

    //
    // The pointers to VMs' info.
    //
    struct vm_info *vm_info[MAX_VM_NUM + 1];

    /* vsock info, indexed by guest_CID which starts from 3 */
    struct vsock_info vsock_info[MAX_VM_NUM + 3];

    /* netlink sock between hypervisor and worker */
    struct sock *nl_sk;
    struct netlink_info netlink_info_list;
    DECLARE_HASHTABLE(worker_hash, 8);

    /* device memory size and usage */
    // TODO: move to device memory policy.
    size_t total_dev_mem;
    size_t used_dev_mem;
    /* mutex */
    struct mutex used_mem_lock;

    /* New policy interface */
    struct task_struct *sched;
    /* scheduling policies */
    struct resource_policy_list policies;
    int max_policy_id;
    struct bpf_policy_list bpf_policies;
    int max_bpf_id;

} KVM_VGPU_PIPE, *PKVM_VGPU_PIPE;

extern struct kvm_vgpu_dev *vgpu_dev;

struct kvm_vgpu_dev *vgpu_dev_instance(void);

void kvm_ava_push_to_send_queue(struct vsock_info *vsock_info,
        struct vhost_virtqueue *vq, struct virtio_vsock_pkt *pkt);
struct pkt_wrapper *kvm_ava_poll_send_queue(struct vsock_info *vsock_info);
int kvm_ava_guest_pkt(struct virtio_vsock_pkt *pkt);
void kvm_ava_host_pkt(struct virtio_vsock_pkt *pkt);

#if AVA_ENABLE_KVM_MEDIATION
void netlink_send_msg(struct app_info *app_info, struct obj_info *obj_info, int direction);
void netlink_recv_msg(struct sk_buff *skb);
#endif

/* kvm_vgpu_init */
void init_vm_info(struct vm_info *vm_info);
void destroy_vm_info(struct vm_info *vm_info);

void init_app_info(struct app_info *app_info,
                   u64 guest_cid, u32 app_port, u32 worker_port,
                   struct vm_info *vm_info);
void destroy_app_info(struct app_info *app_info);

void init_nl_info(struct netlink_info *nl_info,
                  int vm_id, int worker_port, int worker_pid);

#endif
