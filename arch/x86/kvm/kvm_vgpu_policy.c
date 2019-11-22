#include <linux/kernel.h>
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/hrtimer.h>
#include <linux/list.h>
#include <linux/wait.h>

#include <scea/common/devconf.h>
#include <scea/kvm.h>
#include <scea/kvm_policy.h>
#include <scea/kvm_measure.h>

/**
 * Removes all installed policies if @id is non-positive.
 */
void remove_kern_policy(struct resource_policy_list *policies, int id)
{
    struct resource_policy_list *pos, *n;

    list_for_each_entry_safe(pos, n, &policies->list, list)
        if (id <= 0 || pos->id == id) {
            list_del(&pos->list);
            kfree(pos);

            pr_info("kvm-vgpu: remove kern policy#%d\n", pos->id);
            if (pos->id == id) break;
        }
}

/**
 * Removes all attached BPF policies if @id is non-positive.
 */
void detach_bpf_policy(struct bpf_policy_list *policy_list, int id)
{
    struct bpf_policy_list *pos, *n;
    struct bpf_policy *policy;

    list_for_each_entry_safe(pos, n, &policy_list->list, list)
        if (id <= 0 || pos->id == id) {
            list_del(&pos->list);
            policy = pos->policy;

            /* release bpf_prog */
            if (policy->vm_init)
                bpf_prog_put(policy->vm_init);
            if (policy->vm_fini)
                bpf_prog_put(policy->vm_fini);
            if (policy->vm_consume)
                bpf_prog_put(policy->vm_consume);
            if (policy->vm_schedule)
                bpf_prog_put(policy->vm_schedule);

            kfree(policy);
            kfree(pos);

            pr_info("kvm-vgpu: remove bpf policy#%d\n", pos->id);
            if (pos->id == id) break;
        }
}

/* deprecated: to be called at KVM boot time */
void init_vgpu_resource(void) __deprecated
{
    struct resource_policy_list *pos, *n;

    list_for_each_entry_safe(pos, n, &vgpu_dev->policies.list, list) {
        pos->policy->kvm_init();
    }
}

void release_vgpu_resource(void)
{
    struct resource_policy_list *pos, *n;

    list_for_each_entry_safe(pos, n, &vgpu_dev->policies.list, list) {
        if (pos->policy->kvm_release)
            pos->policy->kvm_release();
    }
}

/* to be called at VM boot time */
void init_vm_resource(int vm_id)
{
#ifdef AVA_VSOCK_INTERPOSITION_NOBUF
    struct resource_policy_list *pos, *n;
    struct bpf_policy_list *bpf_pos, *bpf_n;
    struct sk_buff *skb;

    list_for_each_entry_safe(pos, n, &vgpu_dev->policies.list, list) {
        if (pos->policy->vm_init)
            pos->policy->vm_init(vm_id);
    }

    list_for_each_entry_safe(bpf_pos, bpf_n, &vgpu_dev->bpf_policies.list, list) {
        if (bpf_pos->policy->vm_init) {
            skb = alloc_skb(0, GFP_KERNEL);
            skb->protocol = vm_id;
            BPF_PROG_RUN(bpf_pos->policy->vm_init, skb);
            kfree_skb(skb);
        }
    }
#endif
}

void release_vm_resource(int vm_id)
{
#ifdef AVA_VSOCK_INTERPOSITION_NOBUF
    struct resource_policy_list *pos, *n;
    struct bpf_policy_list *bpf_pos, *bpf_n;
    struct sk_buff *skb;

    list_for_each_entry_safe(pos, n, &vgpu_dev->policies.list, list) {
        if (pos->policy->vm_release)
            pos->policy->vm_release(vm_id);
    }

    list_for_each_entry_safe(bpf_pos, bpf_n, &vgpu_dev->bpf_policies.list, list) {
        if (bpf_pos->policy->vm_fini) {
            skb = alloc_skb(0, GFP_KERNEL);
            skb->protocol = vm_id;
            BPF_PROG_RUN(bpf_pos->policy->vm_fini, skb);
            kfree_skb(skb);
        }
    }
#endif
}

/**
 * Invokes the `schedule` BPF program periodically to query the
 * priority/state of the command. It resumes the high-priority commands
 * to be sent to the worker, and delays the low-priority commands.
 *
 * FIXME: The callback response command (from guestapp to worker) **may** be
 * blocked by the previous queued API command (TODO: check the vsock
 * implementation), which can cause a deadlock. The solution can either
 * be using a separate channel for callback response, or reordering
 * the vsock messages.
 */
static void schedule_loop(int vm_id, struct bpf_prog *prog, struct sk_buff *skb)
{
    long num_tries = 0;
    int delay = GPU_SCHEDULE_PERIOD * USEC_PER_MSEC;
    int priority;

    BUG_ON(prog == NULL);
    BUG_ON(skb == NULL);

    do {
        priority = BPF_PROG_RUN(prog, skb);
        if (priority == BPF_AVA_CONTINUE) {
            DEBUG_PRINT("kvm-vgpu: [vm#%d] budget is enough\n", vm_id);
            break;
        }
        else if (likely(priority == BPF_AVA_DELAY)) {
            /* delay fixed-amount of time */
            usleep_range(delay, delay + 50);
        }
    // TODO: move the constant maximum looping time (5000 ms) to
    // configuration file, or remove the loop in a better scheduler design.
    } while ((num_tries++) < 5000 / GPU_SCHEDULE_PERIOD);
}

void check_vm_resource(int vm_id, struct command_base *command, struct sk_buff *skb)
{
    struct resource_policy_list *pos, *n;
    struct bpf_policy_list *bpf_pos, *bpf_n;

    list_for_each_entry_safe(pos, n, &vgpu_dev->policies.list, list) {
        if (pos->policy->vm_check)
            pos->policy->vm_check(vm_id, command);
    }

    list_for_each_entry_safe(bpf_pos, bpf_n, &vgpu_dev->bpf_policies.list, list) {
        if (bpf_pos->policy->vm_schedule)
            schedule_loop(vm_id, bpf_pos->policy->vm_schedule, skb);
    }
}

void consume_vm_resource(struct sk_buff *skb)
{
    struct bpf_policy_list *bpf_pos, *bpf_n;

    list_for_each_entry_safe(bpf_pos, bpf_n, &vgpu_dev->bpf_policies.list, list) {
        if (bpf_pos->policy->vm_consume)
            BPF_PROG_RUN(bpf_pos->policy->vm_consume, skb);
    }
}

/* to be called at guest app start time */
void init_app_resource(struct app_info *app_info)
{
    struct resource_policy_list *pos, *n;

    list_for_each_entry_safe(pos, n, &vgpu_dev->policies.list, list) {
        if (pos->policy->app_init)
            pos->policy->app_init(app_info);
    }
}

void release_app_resource(struct app_info *app_info)
{
    struct resource_policy_list *pos, *n;
    list_for_each_entry_safe(pos, n, &vgpu_dev->policies.list, list) {
        if (pos->policy->app_release)
            pos->policy->app_release(app_info);
    }
}

#if 0
// TODO: move to policy file
void test {
    struct command_base *msg = (struct command_base *)pkt->buf;
    struct sk_buff *skb;
    struct bpf_policy_data *bpf_data;

        vhost_transport_pkt_wrapper(item->pkt);

    //struct timespec start, end;
    if (pkt->len >= sizeof(struct command_base)) {
        DEBUG_PRINT("[kvm_vgpu] receive invocation vm_id=%d, cmd_id=%ld\n", msg->vm_id, msg->command_id);

        //getnstimeofday(&start);
        msg->flags = 0;
        skb = alloc_skb(0, GFP_KERNEL);
        bpf_data = (struct bpf_policy_data *)skb->cb;
        bpf_data->vm_id = msg->vm_id;
        bpf_data->cmd_id = msg->command_id;
        check_vm_resource(vsock_info->vm_id, msg, skb);
        kfree_skb(skb);
        //getnstimeofday(&end);
        //pr_info("BPF check takes %ld ns\n", (end.tv_sec - start.tv_sec) * 1000000000 + end.tv_nsec - start.tv_nsec);
    }
}
#endif
