#include <linux/kernel.h>
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/hrtimer.h>
#include <linux/wait.h>

#include <scea/common/devconf.h>
#include <scea/kvm.h>
#include <scea/kvm_policy.h>
#include <scea/kvm_measure.h>

/* command rate */
static struct command_rate {
    atomic_t balance[MAX_VM_NUM + 1];
    int refill_budget[MAX_VM_NUM + 1];
    int tot_shares;

    struct hrtimer timer;
    unsigned timer_period;
    wait_queue_head_t wq;

    /* moving average for adaptive budget */
    atomic_t simple_count[MAX_VM_NUM + 1];
    int old_commands[MAX_VM_NUM + 1][5];
    int tot_commands[MAX_VM_NUM + 1];
    int old_index[MAX_VM_NUM + 1];
} command_rate;

static enum hrtimer_restart command_rate_timer_callback(struct hrtimer *timer)
{
    int i, k;
    int tot_counts = 0;
    int limit = 0, budget = 0;

    /* moving average */
    for (i = 1; i <= MAX_VM_NUM; i++)
        if (vgpu_dev->vm_ids[i]) {
            k = command_rate.old_index[i];
            command_rate.tot_commands[i] -= command_rate.old_commands[i][k];
            command_rate.old_commands[i][k] = atomic_xchg(&command_rate.simple_count[i], 0);
            command_rate.tot_commands[i] += command_rate.old_commands[i][k];
            command_rate.old_index[i] = (command_rate.old_index[i] + 1) % 5;

            tot_counts += command_rate.old_commands[i][k];

            /*
            printk("old_commands=(%d,%d,%d,%d,%d)\n",
                    command_rate.old_commands[i][0],
                    command_rate.old_commands[i][1],
                    command_rate.old_commands[i][2],
                    command_rate.old_commands[i][3],
                    command_rate.old_commands[i][4]);
            */
        }

    for (i = 1; i <= MAX_VM_NUM; i++)
        if (vgpu_dev->vm_ids[i]) {
            /* use proportional rate when rate > 0.9*max_limit */
            if (tot_counts * 10000 / command_rate.timer_period < COMMAND_RATE_LIMIT_BASE * command_rate.tot_shares * 9) {
                limit = COMMAND_RATE_LIMIT_BASE * command_rate.tot_shares;
                budget = COMMAND_RATE_BUDGET_BASE * command_rate.tot_shares;
            }
            else {
                limit = COMMAND_RATE_LIMIT_BASE * PREDEFINED_RATE_SHARES[i];
                budget = COMMAND_RATE_BUDGET_BASE * PREDEFINED_RATE_SHARES[i];
            }
            if (abs(command_rate.refill_budget[i] - budget) > (COMMAND_RATE_BUDGET_BASE >> 1))
                command_rate.refill_budget[i] = budget;

            /* adaptively update refill budget when rate > 0.8*limit */
            if (command_rate.tot_commands[i] * 1000 / command_rate.timer_period > limit * 4) {
                //printk("estimate rate = %d, old_budget = %d\n", command_rate.tot_commands[i] * 200 / command_rate.timer_period, command_rate.refill_budget[i]);
                if (command_rate.tot_commands[i] * 200 / command_rate.timer_period > limit &&
                        command_rate.refill_budget[i] > budget) {
                    command_rate.refill_budget[i]--;
                }
                else if (command_rate.tot_commands[i] * 200 / command_rate.timer_period < limit &&
                        command_rate.refill_budget[i] <= budget + 3) {
                    command_rate.refill_budget[i]++;
                }
                //printk("new budget = %d\n", command_rate.refill_budget[i]);
            }

            if (likely(atomic_read(&command_rate.balance[i]) > 0)) {
                atomic_set(&command_rate.balance[i], command_rate.refill_budget[i]);
            }
            else {
                atomic_add(command_rate.refill_budget[i], &command_rate.balance[i]);
            }
        }

    wake_up_interruptible(&command_rate.wq);
    hrtimer_forward(timer, hrtimer_cb_get_time(timer), ktime_set(0, command_rate.timer_period * NSEC_PER_MSEC));

    return HRTIMER_RESTART;
}

static void init_command_rate(void)
{
    int i;
    ktime_t kt;

    for (i = 1; i <= MAX_VM_NUM; i++)
        atomic_set(&command_rate.balance[i], 0);

    command_rate.timer_period = COMMAND_RATE_PERIOD_INIT;
    init_waitqueue_head(&command_rate.wq);
    command_rate.tot_shares = 0;

    /* start periodic timer */
    hrtimer_init(&command_rate.timer, CLOCK_REALTIME, HRTIMER_MODE_ABS);
    kt = ktime_set(0, command_rate.timer_period * NSEC_PER_MSEC);
    command_rate.timer.function = &command_rate_timer_callback;
    hrtimer_start(&command_rate.timer, kt, HRTIMER_MODE_ABS);

    AVA_MEASURE(init_command_rate_measure);
}

static void release_command_rate(void)
{
    hrtimer_cancel(&command_rate.timer);
}

static void init_vm_command_rate(int vm_id)
{
    int i;

    /* NOTE: we implement account-level limiting at vm-level. */
    command_rate.tot_shares += PREDEFINED_RATE_SHARES[vm_id];
    for (i = 1; i <= MAX_VM_NUM; i++)
        if (vgpu_dev->vm_ids[i])
            command_rate.refill_budget[i] = COMMAND_RATE_BUDGET_BASE * command_rate.tot_shares;

    atomic_set(&command_rate.balance[vm_id], command_rate.refill_budget[vm_id]);

    atomic_set(&command_rate.simple_count[vm_id], 0);
    memset(command_rate.old_commands[vm_id], 0, sizeof(int) * 5);
    command_rate.old_index[vm_id] = 0;
    command_rate.tot_commands[vm_id] = 0;
}

static void release_vm_command_rate(int vm_id)
{
    int i;
    command_rate.tot_shares -= PREDEFINED_RATE_SHARES[vm_id];
    for (i = 1; i <= MAX_VM_NUM; i++)
        if (vgpu_dev->vm_ids[i])
            command_rate.refill_budget[i] = COMMAND_RATE_BUDGET_BASE * command_rate.tot_shares;
}

static void check_vm_command_rate(int vm_id, struct command_base *command)
{
    if (atomic_read(&command_rate.balance[vm_id]) <= 0) {
        DEBUG_PRINT("vm#%d has no enough command rate budget (%d)\n",
                    vm_id, atomic_read(&command_rate.balance[vm_id]));
        wait_event_interruptible(command_rate.wq,
                atomic_read(&command_rate.balance[vm_id]) > 0);
    }
}

// TODO: provide unique interface
void consume_vm_command_rate(int vm_id, int consumed)
{
    atomic_sub(consumed, &command_rate.balance[vm_id]);
    atomic_add(consumed, &command_rate.simple_count[vm_id]);
    AVA_MEASURE(count_command_rate_measure, vm_id, consumed);
}

struct resource_policy command_rate_func = {
    .kvm_init = init_command_rate,
    .kvm_release = release_command_rate,

    .vm_init = init_vm_command_rate,
    .vm_release = release_vm_command_rate,
    .vm_check = check_vm_command_rate,

    .app_init = NULL,
    .app_release = NULL,
};
EXPORT_SYMBOL_GPL(command_rate_func);
