/**
 * TODO: A policy needs multiple functions, of which the most important are the
 * consumer function (/consume) and checker function (/check). So we need to
 * support downloading multiple BPF programs to the hypervisor. This requires
 * the following changes:
 * 1. Save BPF programs into fixed positions in `prog_fd[]`;
 * 2. Download the whole prog_fd[] to the hypervisor.
 *
 * TODO: Data such as the amount of the consumed resource needs to be passed
 * to the BPF program, which requires to implement a specific BPF load instruction.
 * Other new instructions may need to be added as well.
 */

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include "bpf_helpers.h"
#include "scea/common/devconf.h"
#include "scea/common/bpf.h"

struct bpf_map_def SEC("maps") command_cnt = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(unsigned long),
	.max_entries = 32,
};

struct bpf_map_def SEC("maps") priority = {
    .type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(unsigned int),
	.max_entries = 32,
};

struct bpf_map_def SEC("maps") prev_ts = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = 32,
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
SEC("ava_policy/command_rate/consume")
int bpf_consume(struct __sk_buff *skb)
{
    if (skb == NULL) return BPF_AVA_ERROR;

    int vm_id = bpf_load_ava_vm_id(skb), tot_id = 0;
    long *cnt, *tot_cnt;
    long rc_amount = bpf_load_ava_rc_amount(skb);

    char fmt[] = "vm_id=%d, rc_amount=%ld\n";
    bpf_trace_printk(fmt, sizeof(fmt), vm_id, rc_amount);


	cnt = bpf_map_lookup_elem(&command_cnt, &vm_id);
	tot_cnt = bpf_map_lookup_elem(&command_cnt, &tot_id);
    if (tot_cnt)
        __sync_fetch_and_add(tot_cnt, rc_amount);
	if (cnt)
		__sync_fetch_and_add(cnt, rc_amount);

	return BPF_AVA_SUCCESS;
}

SEC("ava_policy/command_rate/schedule")
long bpf_schedule(struct __sk_buff *skb)
{
    if (skb == NULL) return BPF_AVA_ERROR;

    int vm_id = bpf_load_ava_vm_id(skb), tot_id = 0;

    char fmt[] = "vm_id=%d\n";
    bpf_trace_printk(fmt, sizeof(fmt), vm_id);

    u64 *ts = bpf_map_lookup_elem(&prev_ts, &vm_id);
	unsigned long *cnt = bpf_map_lookup_elem(&command_cnt, &vm_id), *tot_cnt;
	unsigned int *pri = bpf_map_lookup_elem(&priority, &vm_id);

    /* period is 1e5 ns */
    u64 cur_ts = bpf_ktime_get_ns() / (unsigned int)1e5;
    if (ts && cnt && (*ts) != cur_ts) {
        *ts = cur_ts;
        tot_cnt = bpf_map_lookup_elem(&command_cnt, &tot_id);
        if (tot_cnt) *tot_cnt -= *cnt;
        *cnt = 0;
    }

    /* returns priority, smaller number means higher priority */
    if (cnt && pri && *pri != 0)
        return (*cnt) / (*pri);
    else
    	return BPF_AVA_ERROR;
}

SEC("ava_policy/command_rate/vm_init")
int bpf_init(struct __sk_buff *skb)
{
    int vm_id = bpf_load_ava_vm_id(skb);

    /* clear time counters */
    long *value = bpf_map_lookup_elem(&command_cnt, &vm_id);
    u64 *ts = bpf_map_lookup_elem(&prev_ts, &vm_id);

	if (value)
        *value = 0;
    if (ts)
        *ts = 0;

    /* check priority */
	unsigned int *pri = bpf_map_lookup_elem(&priority, &vm_id);
    if (pri && *pri > 0)
	    return 0;
    else
        return BPF_AVA_ERROR;
}

SEC("ava_policy/command_rate/vm_fini")
int bpf_fini(struct __sk_buff *skb)
{
//    char fmt[] = "%p, %p, %x\n";
//    bpf_trace_printk(fmt, sizeof(fmt), skb, data, index);

    return 0;
}

char _license[] SEC("license") = "GPL";
