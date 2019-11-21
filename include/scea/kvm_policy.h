#ifndef __KVM_VGPU_POLICY_H__
#define __KVM_VGPU_POLICY_H__

#include <linux/bpf.h>
#include <linux/circ_buf.h>
#include <linux/list.h>
#include <linux/semaphore.h>
#include <linux/skbuff.h>
#include <linux/vhost.h>
#include <linux/virtio_vsock.h>

#include <scea/common/bpf.h>
#include <scea/common/cmd_channel.h>
#include <scea/kvm.h>

/* Queues for scheduler */
struct vsock_info;

struct pkt_wrapper {
    struct virtio_vsock_pkt *pkt;
    struct vhost_virtqueue *vq;
};

struct circ_send_queue {
	struct pkt_wrapper *buf;
	int head;
	int tail;
    unsigned long size;
    struct semaphore sem_empty;
    struct semaphore sem_full;
};

/* interfaces */
struct app_info;

struct resource_policy {
    void (*kvm_init)(void);
    void (*kvm_release)(void);

    void (*vm_init)(int vm_id);
    void (*vm_release)(int vm_id);
    void (*vm_check)(int vm_id, struct command_base *command);

    void (*app_init)(struct app_info *app_info);
    void (*app_release)(struct app_info *app_info);
};

struct resource_policy_list {
    struct list_head list;
    struct resource_policy *policy;
    int id;
};

void remove_kern_policy(struct resource_policy_list *policies, int id);

/* policies */
void init_vgpu_resource(void);
void release_vgpu_resource(void);

void init_vm_resource(int vm_id);
void release_vm_resource(int vm_id);
void check_vm_resource(int vm_id, struct command_base *command, struct sk_buff *skb);
void consume_vm_resource(struct sk_buff *skb);

void consume_vm_command_rate(int vm_id, int consumed);
void consume_vm_device_time(int vm_id, long consumed);
void consume_vm_device_time_hp(int vm_id, long consumed);
void consume_vm_device_memory(struct app_info *app_info, long consumed);
void consume_vm_device_memory_limit(int vm_id, long consumed);
void consume_vm_qat_throughput(int vm_id, long consumed);

void init_app_resource(struct app_info *app_info);
void release_app_resource(struct app_info *app_info);

/* BPF interfaces */
struct bpf_policy_data {
    int vm_id;
    int cmd_id;
    long rc_amount;

    struct command_base *command;
    // TODO: struct can be expanded
};

struct bpf_policy {
    /* func(int vm_id) */
    struct bpf_prog *vm_init;
    /* func(int vm_id) */
    struct bpf_prog *vm_fini;
    /* func(int vm_id, struct command_base *command) */
    struct bpf_prog *vm_schedule;
    /* func(int vm_id, long long consumed) */
    struct bpf_prog *vm_consume;
};

struct bpf_policy_list {
    struct list_head list;
    struct bpf_policy *policy;
    int id;
};

void detach_bpf_policy(struct bpf_policy_list *policy_list, int id);

#endif
