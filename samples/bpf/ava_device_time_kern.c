#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include "bpf_helpers.h"
#include "scea/common/devconf.h"
#include "scea/common/bpf.h"

/**
 * Entry[0] counts the total device time used by all VMs.
 */
struct bpf_map_def SEC("maps") device_time = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(unsigned long),
	.max_entries = MAX_VM_NUM + 1,
};

struct bpf_map_def SEC("maps") priority = {
    .type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(int),
	.max_entries = MAX_VM_NUM + 1,
};

struct bpf_map_def SEC("maps") prev_ts = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = MAX_VM_NUM + 1,
};

/**
 * Lock:
 * For some policies the BPF programs may need to be protected by spin locks.
 * Since kernel 5.1 BPF supports `bpf_spin_lock` and `BPF_F_LOCK` map flag,
 * but before that the BPF program should be guarded by spin locks.
 *
 * Load:
 * Ideally, the BPF program should be able to read the packets but have no write
 * permission.
 */
SEC("ava_policy/device_time/consume")
int bpf_consume(struct __sk_buff *skb)
{
    if (skb == NULL) return BPF_AVA_ERROR;

    int vm_id = bpf_load_ava_vm_id(skb), tot_id = 0;

    long *dev_time = bpf_map_lookup_elem(&device_time, &vm_id);
    long *tot_dev_time = bpf_map_lookup_elem(&device_time, &tot_id);
    long rc_amount = bpf_load_ava_rc_amount(skb);

    char fmt[] = "vm_id=%d, rc_amount=%ld\n";
    bpf_trace_printk(fmt, sizeof(fmt), vm_id, rc_amount);

	if (dev_time)
		__sync_fetch_and_add(dev_time, rc_amount);
    if (tot_dev_time)
        __sync_fetch_and_add(tot_dev_time, rc_amount);

	return BPF_AVA_SUCCESS;
}

SEC("ava_policy/device_time/schedule")
int bpf_schedule(struct __sk_buff *skb)
{
    if (skb == NULL) return BPF_AVA_ERROR;

    int vm_id = bpf_load_ava_vm_id(skb), tot_id = 0;

    u64 *ts = bpf_map_lookup_elem(&prev_ts, &vm_id);
    long *dev_time = bpf_map_lookup_elem(&device_time, &vm_id);
    long *tot_dev_time = bpf_map_lookup_elem(&device_time, &tot_id);
	int *pri = bpf_map_lookup_elem(&priority, &vm_id);
    int *tot_pri = bpf_map_lookup_elem(&priority, &tot_id);

    /* period is 1e5 ns */
    u64 cur_ts = bpf_ktime_get_ns() / (unsigned int)1e5;
    if (ts && (*ts) != cur_ts) {
        *ts = cur_ts;
        if (dev_time && tot_dev_time) {
            *tot_dev_time -= *dev_time;
            *dev_time = 0;
        }
    }

    if (dev_time && pri && tot_dev_time && tot_pri &&
            (*dev_time) * (*tot_pri) <= (*pri) * (*tot_dev_time))
        return BPF_AVA_CONTINUE;
    else
    	return BPF_AVA_DELAY;
}

SEC("ava_policy/device_time/vm_init")
int bpf_init(struct __sk_buff *skb)
{
    int vm_id = bpf_load_ava_vm_id(skb), tot_id = 0;

    /* clear time counters */
    long *dev_time = bpf_map_lookup_elem(&device_time, &vm_id);
    u64 *ts = bpf_map_lookup_elem(&prev_ts, &vm_id);

	if (dev_time)
        *dev_time = 0;
    if (ts)
        *ts = 0;

    /* check priority */
	unsigned int *pri = bpf_map_lookup_elem(&priority, &vm_id);
	unsigned int *tot_pri = bpf_map_lookup_elem(&priority, &tot_id);
    if (pri && *pri > 0) {
        if (tot_pri)
            *tot_pri += *pri;
	    return 0;
    }
    else
        return BPF_AVA_ERROR;
}

SEC("ava_policy/device_time/vm_fini")
int bpf_fini(struct __sk_buff *skb)
{
    int vm_id = bpf_load_ava_vm_id(skb), tot_id = 0;

    /* clear counters */
    long *dev_time = bpf_map_lookup_elem(&device_time, &vm_id);
    long *tot_dev_time = bpf_map_lookup_elem(&device_time, &tot_id);
    if (dev_time && tot_dev_time) {
        *tot_dev_time -= *dev_time;
        *dev_time = 0;
    }

    /* clear priority */
	unsigned int *pri = bpf_map_lookup_elem(&priority, &vm_id);
	unsigned int *tot_pri = bpf_map_lookup_elem(&priority, &tot_id);
    if (pri && tot_pri) {
        *tot_pri -= *pri;
        *pri = 0;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
