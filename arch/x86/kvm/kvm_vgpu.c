#include <scea/common/devconf.h>
#include <scea/common/socket.h>
#include <scea/kvm.h>
#include <scea/kvm_policy.h>

#include <linux/circ_buf.h>
#include <linux/delay.h>
#include <linux/printk.h>
#include <linux/virtio_vsock.h>

/* Returns vgpu_dev instance */
struct kvm_vgpu_dev *vgpu_dev_instance(void)
{
    return vgpu_dev;
}
EXPORT_SYMBOL_GPL(vgpu_dev_instance);

/* look for application that it belongs to */
static struct app_info *get_app_info(struct vm_info *vm_info,
                                     u64 guest_cid,
                                     u32 app_port,
                                     u32 worker_port) {
    struct app_info *pos, *n, *res = NULL;

    list_for_each_entry_safe(pos, n, &vm_info->app_info_list.list, list)
        if (pos->app_cid == guest_cid && pos->app_port == app_port &&
            pos->worker_port == worker_port) {
            DEBUG_PRINT("[kvm_vgpu] searched object for app cid=%llu port=%u worker_port=%u\n",
                        guest_cid, app_port, worker_port);
            res = pos;
            break;
        }

    if (!res)
        pr_err("kvm-vgpu: app_info not found\n");
    return res;
}

static struct app_info *get_app_info_by_worker_pid(struct vm_info *vm_info,
                                                   u32 worker_pid) {
    struct app_info *pos, *n, *res = NULL;

    list_for_each_entry_safe(pos, n, &vm_info->app_info_list.list, list)
        if (pos->worker_pid == worker_pid) {
            DEBUG_PRINT("[kvm_vgpu] searched object for app with worker_pid=%u\n",
                        worker_pid);
            res = pos;
            break;
        }

    if (!res)
        pr_err("kvm-vgpu: app_info not found\n");
    return res;
}

/*! \brief Push the packet into the temporary send queue.
 *
 *  The send queue is polled by the scheduler.
 *  Ideally, this API and the ring buffer structure should be defined by the
 *  scheduling policy to meet different requirements, which however can
 *  leave burden to the policy implementation and verification. So the
 *  current approach is to define an unified ring buffer structure and
 *  policy interface.
 *
 *  @param vsock_info the VSOCK info of the guest's connection
 *  @param vq the virtqueue of the VSOCK connection
 *  @param pkt the packet sent by the guest; vhost_nofity if NULL
 */
void kvm_ava_push_to_send_queue(struct vsock_info *vsock_info,
        struct vhost_virtqueue *vq, struct virtio_vsock_pkt *pkt)
{
    /* The send queue is protected by vq->mutex */
    struct circ_send_queue *sq = &vsock_info->sq;
    unsigned long head, tail;

    BUG_ON(vq == NULL && pkt == NULL);

    /* TODO: semaphore may not be needed */
    down(&sq->sem_full);
    head = sq->head;
    tail = READ_ONCE(sq->tail);

    if (CIRC_SPACE(head, tail, sq->size) >= 1) {
        /* Insert one packet into the buffer. In future, we can add a
         * policy callback here to let policy insert additional
         * scheduling information to the packet wrapper */
        struct pkt_wrapper *item = &sq->buf[head];
        item->pkt = pkt;
        item->vq = vq;

        smp_store_release(&sq->head, (head + 1) & (sq->size - 1));
        up(&sq->sem_empty);
	}
}
EXPORT_SYMBOL_GPL(kvm_ava_push_to_send_queue);

/*! \brief Poll the packet from the temporary send queue.
 *
 *  @param vsock_info the VSOCK info of the guest's connection
 *  @return the wrapper of the polled packet
 */
struct pkt_wrapper *kvm_ava_poll_send_queue(struct vsock_info *vsock_info)
{
    struct circ_send_queue *sq = &vsock_info->sq;
    unsigned long head, tail;
    struct pkt_wrapper *ret = NULL;

    if (vsock_info->vsock == NULL)
        return NULL;

repoll_send_queue:
    if (down_trylock(&sq->sem_empty))
        return NULL;
    head = smp_load_acquire(&sq->head);
    tail = sq->tail;

    if (CIRC_CNT(head, tail, sq->size) >= 1) {

        /* extract one item from the buffer */
        struct pkt_wrapper *item = &sq->buf[tail];
        if (item->pkt == NULL) {
            DEBUG_PRINT("[kvm-vgpu] signal vhost\n");
            vsock_info->vhost_signal_helper(vsock_info, item);
            smp_store_release(&sq->tail, (tail + 1) & (sq->size - 1));
            up(&sq->sem_full);
            goto repoll_send_queue;
        }

        DEBUG_PRINT("[kvm-vgpu] poll a pkt\n");
        ret = kmalloc(sizeof(struct pkt_wrapper), GFP_KERNEL);
        memcpy(ret, item, sizeof(struct pkt_wrapper));
        smp_store_release(&sq->tail, (tail + 1) & (sq->size - 1));
        up(&sq->sem_full);
    }

    return ret;
}
EXPORT_SYMBOL_GPL(kvm_ava_poll_send_queue);

/*! \brief Interpose the packets sent from guestlib to worker.
 *
 *  This interposition interprets the command packet sent by guestlib
 *  to worker, and determines the spawn and shutdown of the guestlib.
 *
 *  @param pkt the packet sent from guestlib
 *  @return 0 if the packet is for a command, 1 otherwise
 */
int kvm_ava_guest_pkt(struct virtio_vsock_pkt *pkt)
{
	u64 guest_cid = le64_to_cpu(pkt->hdr.src_cid);
    u32 src_port = le32_to_cpu(pkt->hdr.src_port);
    u32 dst_port = le32_to_cpu(pkt->hdr.dst_port);
    u16 op = le16_to_cpu(pkt->hdr.op);

    struct vsock_info *vsock_info = &vgpu_dev->vsock_info[guest_cid];
    struct vm_info *vm_info = vsock_info->vm_info;
    struct app_info *new_app_info, *pos, *n;

#ifdef AVA_VSOCK_INTERPOSITION_NOBUF
    struct command_base *msg = (struct command_base *)pkt->buf;
    struct sk_buff *skb;
    struct bpf_policy_data *bpf_data;
#endif

    DEBUG_PRINT("[kvm_vgpu] interpose pkt (op=%u) from guest (cid#%llu) to worker (port=%u,len=%x)\n",
                op, guest_cid, dst_port, pkt->len);

    if (dst_port == WORKER_MANAGER_PORT) return 1;

    /* create app_info for new guest applications */
    if (pkt->len == 0) {
        u32 flags = le32_to_cpu(pkt->hdr.flags);

        if (op == VIRTIO_VSOCK_OP_REQUEST) {
            DEBUG_PRINT("[kvm_vgpu] GUEST_OP_REQUEST cid=%llu port=%u, worker_port=%u flags=%u\n",
                        guest_cid, src_port, dst_port, flags);

            new_app_info = (struct app_info *)kmalloc(sizeof(struct app_info), GFP_KERNEL);
            init_app_info(new_app_info, guest_cid, src_port, dst_port, vm_info);

#ifdef AVA_VSOCK_INTERPOSITION_NOBUF
            init_app_resource(new_app_info);
#endif
        }
        else if (op == VIRTIO_VSOCK_OP_SHUTDOWN) {
            DEBUG_PRINT("[kvm_vgpu] GUEST_OP_SHUTDOWN flags=%u\n", flags);

            list_for_each_entry_safe(pos, n, &vm_info->app_info_list.list, list)
                if (pos->app_cid == guest_cid && pos->app_port == src_port &&
                    pos->worker_port == dst_port) {
                    DEBUG_PRINT("[kvm_vgpu] delete app_info cid=%llu port=%u worker_port=%u\n",
                                guest_cid, src_port, dst_port);

#ifdef AVA_VSOCK_INTERPOSITION_NOBUF
                    release_app_resource(pos);
#endif
                    destroy_app_info(pos);
                    break;
                }
        }

        return 1;
    }

#ifdef AVA_VSOCK_INTERPOSITION_NOBUF
    if (pkt->len >= sizeof(struct command_base)) {
        DEBUG_PRINT("[kvm_vgpu] receive invocation vm_id=%d, cmd_id=%ld\n", msg->vm_id, msg->command_id);
        msg->flags = 0;
        skb = alloc_skb(0, GFP_KERNEL);
        bpf_data = (struct bpf_policy_data *)skb->cb;
        bpf_data->vm_id = msg->vm_id;
        bpf_data->cmd_id = msg->command_id;
        check_vm_resource(vsock_info->vm_id, msg, skb);
        kfree_skb(skb);
    }
#endif

    return 0;
}
EXPORT_SYMBOL_GPL(kvm_ava_guest_pkt);

/*! \brief Interpose the packets sent from worker to guestlib.
 *
 *  This interposition interprets the response packet sent by worker to
 *  guestlib, and determines the shutdown of the worker.
 *
 *  @param pkt the packet sent from worker
 */
void kvm_ava_host_pkt(struct virtio_vsock_pkt *pkt)
{
    struct command_base *msg = (struct command_base *)pkt->buf;
    u64 guest_cid = le64_to_cpu(pkt->hdr.dst_cid);
    u32 src_port = le32_to_cpu(pkt->hdr.src_port);
    u32 dst_port = le32_to_cpu(pkt->hdr.dst_port);
    u16 op = le16_to_cpu(pkt->hdr.op);

    struct vsock_info *vsock_info = &vgpu_dev->vsock_info[guest_cid];
    struct vm_info *vm_info = vsock_info->vm_info;
    struct app_info *app_info;

    DEBUG_PRINT("[kvm_vgpu] interpose pkt (op=%u) from worker (port=%u,len=%x) to guest (cid#%llu)\n",
                op, src_port, pkt->len, guest_cid);

    if (src_port == WORKER_MANAGER_PORT) return;

    /* Used for debugging. The message requires a magic header (for
     * verification) if we want to interpose the response message */
    if (pkt->len >= sizeof(struct command_base)) {
        DEBUG_PRINT("[kvm_vgpu] response message from host vm_id=%d, cmd_id=%ld\n",
                msg->vm_id, msg->command_id);
    }

    /* Worker terminates before guestlib when it crashes on API executions */
    if (pkt->len == 0 && op == VIRTIO_VSOCK_OP_SHUTDOWN) {
        DEBUG_PRINT("[kvm_vgpu] WORKER_OP_SHUTDOWN flags=%u\n", le32_to_cpu(pkt->hdr.flags));

        app_info = get_app_info(vm_info, guest_cid, dst_port, src_port);
        DEBUG_PRINT("[kvm_vgpu] delete app_info (cid=%llu port=%u worker_port=%u)\n",
                    guest_cid, dst_port, src_port);

#ifdef AVA_VSOCK_INTERPOSITION_NOBUF
        release_app_resource(app_info);
#endif
        destroy_app_info(app_info);
    }
}
EXPORT_SYMBOL_GPL(kvm_ava_host_pkt);

#ifdef AVA_ENABLE_KVM_MEDIATION
/* Receive messages from worker */
void netlink_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)skb->data;
    struct command_base *msg = (struct command_base *)nlmsg_data(nlh);
    struct netlink_info *nl_info;
    struct vm_info *vm_info;
    struct app_info *app_info;
    int worker_pid = nlh->nlmsg_pid;
    struct netlink_info *whnode;
    int vm_id = -1;

    struct sk_buff *fake_skb;
    struct bpf_policy_data *bpf_data;
    struct bpf_policy_list *pos, *n;
    //struct timespec start, end;

    BUG_ON(msg->api_id != INTERNAL_API);

    if (msg->command_id == NW_NEW_WORKER) {
        vm_id = 0;
    }
    else {
        hash_for_each_possible(vgpu_dev->worker_hash, whnode, node, nlh->nlmsg_pid) {
            if (whnode->worker_pid != nlh->nlmsg_pid)
                continue;
            vm_id = whnode->vm_id;
            break;
        }
        BUG_ON((vm_id <= 0 || vm_id > MAX_VM_NUM));
    }

    vm_info = vgpu_dev->vm_info[vm_id];
    DEBUG_PRINT("receive netlink message cmd_id=%ld\n", msg->command_id);

    /* iterate BPF policies.
     * TODO: need to find the specific policy by `api_id` and `resource_type`. */
    if (msg->command_id == CONSUME_RC_COMMAND_RATE) {
        //getnstimeofday(&start);
        fake_skb = alloc_skb(0, GFP_KERNEL);
        bpf_data = (struct bpf_policy_data *)fake_skb->cb;
        bpf_data->vm_id = vm_id;
        bpf_data->rc_amount = *(long *)msg->reserved_area;
        consume_vm_resource(fake_skb);
        kfree_skb(fake_skb);
        //getnstimeofday(&end);
        //pr_info("BPF consume takes %ld ns\n", (end.tv_sec - start.tv_sec) * 1000000000 + end.tv_nsec - start.tv_nsec);
    }

    /* process commands */
    switch (msg->command_id)
    {
        case NW_NEW_WORKER:
            DEBUG_PRINT("kvm-vgpu: new_worker vm_id=%d, port=%d, pid=%d\n",
                        vm_id,
                        *(int *)msg->reserved_area,
                        nlh->nlmsg_pid);

            nl_info = (struct netlink_info *)kmalloc(sizeof(struct netlink_info), GFP_KERNEL);
            // FIXME: vm_id is set by guestlib not worker
            init_nl_info(nl_info, 0, *(int *)msg->reserved_area, worker_pid);
            break;

        case CONSUME_RC_DEVICE_TIME:
            /* update GPU time budget when invocation is handled */
            DEBUG_PRINT("kvm-vgpu: [vm#%d] took %ld usecs\n",
                        vm_id, *(long *)msg->reserved_area);
            consume_vm_device_time_hp(vm_id, *(long *)msg->reserved_area);

            // TODO: Design unique interface and put this loop outside the
            // switch.
            list_for_each_entry_safe(pos, n, &vgpu_dev->bpf_policies.list, list) {
                if (pos->policy->vm_consume)
                    BPF_PROG_RUN(pos->policy->vm_consume, skb);
            }

            break;

        case CONSUME_RC_COMMAND_RATE:
            DEBUG_PRINT("kvm-vgpu: [vm#%d] consumed %d command(s)\n",
                        vm_id, *(int *)msg->reserved_area);
            consume_vm_command_rate(vm_id, *(int *)msg->reserved_area);
            break;

#if EXPERIMENTAL_CODE
        case CONSUME_RC_QAT_THROUGHPUT:
            DEBUG_PRINT("kvm-vgpu: [vm#%d] consumed %ld qat throughput\n",
                        vm_id, *(long *)msg->reserved_area);
            consume_vm_qat_throughput(vm_id, *(long *)msg->reserved_area);
            break;

        case CONSUME_RC_DEVICE_MEMORY:
            DEBUG_PRINT("kvm-vgpu: [vm#%d] %sallocates %lx memory\n",
                        vm_id,
                        *(long *)msg->reserved_area >= 0 ? "":"de",
                        *(long *)msg->reserved_area >= 0 ? *(long *)msg->reserved_area : -*(long *)msg->reserved_area);
            app_info = get_app_info_by_worker_pid(vm_info, worker_pid);
            consume_vm_device_memory(app_info, *(long *)msg->reserved_area);
            consume_vm_device_memory_limit(vm_id, *(long *)msg->reserved_area);
            break;

        case COMMAND_MSG_SWAPPING:
            app_info = get_app_info_by_worker_pid(vm_info, worker_pid);
            if (msg->command_id == COMMAND_SWAP_OUT) {
                DEBUG_PRINT("worker port=%u pid=%u completed swap-out\n",
                            app_info->worker_port, app_info->worker_pid);
            }
            else if (msg->command_id == COMMAND_SWAP_IN) {
                DEBUG_PRINT("worker port=%u pid=%u completed swap-in\n",
                            app_info->worker_port, app_info->worker_pid);
            }
            break;
#endif

        default:
            pr_err("vgpu-kvm: netlink receives wrong message\n");
    }
}

/* Send messages to worker */
void netlink_send_msg(struct app_info *app_info, struct obj_info *obj_info, int direction)
{
    struct sk_buff *skb_out = nlmsg_new(sizeof(struct command_base), 0);
    struct command_base *msg;
    struct nlmsghdr *nlh;
    int ret;

    if (!skb_out) {
        pr_err("vgpu-kvm: failed to allocate new netlink skb");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, sizeof(struct command_base), 0);
    msg = (struct command_base *)nlmsg_data(nlh);
    NETLINK_CB(skb_out).dst_group = 0;

    msg->api_id = INTERNAL_API;
    msg->command_id = direction;

    ret = nlmsg_unicast(vgpu_dev->nl_sk, skb_out, app_info->worker_pid);
    if (ret < 0) {
        pr_err("vgpu-kvm: failed to send to worker via netlink");
    }
}
#endif
