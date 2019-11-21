#include <linux/kernel.h>
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/hrtimer.h>
#include <linux/wait.h>

#include <scea/common/devconf.h>
#include <scea/kvm.h>
#include <scea/kvm_policy.h>
#include <scea/kvm_measure.h>

/* device time */
static struct device_time {
    uint64_t period;

    atomic_t live_app_num[MAX_VM_NUM + 1];
    int priorities[MAX_VM_NUM + 1];
    atomic_t total_priority;

    atomic64_t used_time[MAX_VM_NUM + 1];
    atomic64_t total_used_time;

    atomic_t delay[MAX_VM_NUM + 1]; /* us */
    int old_time[MAX_VM_NUM + 1][5];
    int old_index[MAX_VM_NUM + 1];
} device_time;

static void init_device_time(void)
{
    int i;
    atomic64_set(&device_time.total_used_time, 0);
    for (i = 1; i <= MAX_VM_NUM; i++)
        atomic_set(&device_time.live_app_num[i], 0);

    AVA_MEASURE(init_device_time_measure);
}

static void check_vm_device_time(int vm_id, struct command_base *command)
{
    long tot_used_time, vm_used_time, num_tries = 0;
    int delay;

    do {
        tot_used_time = atomic64_read(&device_time.total_used_time);
        vm_used_time = atomic64_read(&device_time.used_time[vm_id]);
        DEBUG_PRINT("vgpu-kvm: [vm#%d] used time = %ld us, proportion = %d/%d, total used = %ld us\n",
                    vm_id, vm_used_time,
                    device_time.priorities[vm_id],
                    atomic_read(&device_time.total_priority),
                    tot_used_time);

        if (vm_used_time * atomic_read(&device_time.total_priority) <= tot_used_time * device_time.priorities[vm_id]) {
            DEBUG_PRINT("kvm-vgpu: [vm#%d] budget is enough\n", vm_id);

            /* add adaptive delay */
            #if 0
            delay = atomic_read(&device_time.delay[vm_id]);
            if (delay / DEVICE_TIME_DELAY_MUL_DEC > 500)
                atomic_set(&device_time.delay[vm_id], delay / DEVICE_TIME_DELAY_MUL_DEC);
            else
                atomic_set(&device_time.delay[vm_id], 500);
            DEBUG_PRINT("kvm-vgpu: [vm#%d] delay decreased to %d\n", vm_id, atomic_read(&device_time.delay[vm_id]));
            #endif
            break;
        }
        else {
            /* delay fixed-amount of time */
            #if 0
            //msleep(GPU_SCHEDULE_PERIOD);
            usleep_range(GPU_SCHEDULE_PERIOD * USEC_PER_MSEC,
                    GPU_SCHEDULE_PERIOD * USEC_PER_MSEC + 50);
            #endif

            /* add adaptive delay */
            #if 0
            delay = atomic_read(&device_time.delay[vm_id]);
            if (delay < 10 * USEC_PER_MSEC)
                atomic_add(DEVICE_TIME_DELAY_ADD * USEC_PER_MSEC, &device_time.delay[vm_id]);
            else
                atomic_set(&device_time.delay[vm_id], 10 * USEC_PER_MSEC);
            DEBUG_PRINT("kvm-vgpu: [vm#%d] delay increased to %d\n", vm_id, atomic_read(&device_time.delay[vm_id]));
            usleep_range(delay, delay + 50);
            #endif

            /* moving average */
            #if 1
            delay = atomic_read(&device_time.delay[vm_id]) / 2;
            if (delay > 10 * USEC_PER_MSEC)
                delay = 10 * USEC_PER_MSEC;
            if (delay < 500)
                delay = 500;
            usleep_range(delay, delay + 50);
            #endif
        }
    } while (num_tries++ < 5000 / GPU_SCHEDULE_PERIOD);
}

static void init_app_device_time(struct app_info *app_info)
{
    int vm_id = app_info->vm_id;
    int i;

    if (atomic_inc_return(&device_time.live_app_num[vm_id]) == 1) {
        device_time.priorities[vm_id] = PREDEFINED_PRIORITIES[vm_id];
        atomic_add(device_time.priorities[vm_id], &device_time.total_priority);
        atomic64_set(&device_time.used_time[vm_id], 0);

        for (i = 0; i < 5; i++)
            device_time.old_time[vm_id][i] = GPU_SCHEDULE_PERIOD * USEC_PER_MSEC / 5;
        device_time.old_index[vm_id] = 0;
        atomic_set(&device_time.delay[vm_id], GPU_SCHEDULE_PERIOD * USEC_PER_MSEC);
    }
}

static void release_app_device_time(struct app_info *app_info)
{
    int vm_id = app_info->vm_id;

    if (atomic_dec_and_test(&device_time.live_app_num[vm_id])) {
        atomic_sub(device_time.priorities[vm_id], &device_time.total_priority);
        device_time.priorities[vm_id] = 0;
        atomic64_sub(atomic64_read(&device_time.used_time[vm_id]), &device_time.total_used_time);
        atomic64_set(&device_time.used_time[vm_id], 0);
        DEBUG_PRINT("vgpu-kvm: [vm#%d] frees budget, current total_priority = %d\n",
                    vm_id, atomic_read(&device_time.total_priority));
    }
}

void consume_vm_device_time(int vm_id, long consumed)
{
    int delay, k;

    atomic64_add(consumed, &device_time.used_time[vm_id]);
    atomic64_add(consumed, &device_time.total_used_time);
    DEBUG_PRINT("vgpu-kvm: [vm#%d] spent budge = %ld us, used time = %ld us, proportion = %d/%d, total used = %ld us\n",
                vm_id, consumed,
                atomic64_read(&device_time.used_time[vm_id]),
                device_time.priorities[vm_id],
                atomic_read(&device_time.total_priority),
                atomic64_read(&device_time.total_used_time));
    AVA_MEASURE(count_device_time_measure, vm_id, consumed);

    /* compute delay by moving average */
    #if 1
    k = device_time.old_index[vm_id];
    delay = consumed / 5 - device_time.old_time[vm_id][k];
    device_time.old_time[vm_id][k] = consumed / 5;
    device_time.old_index[vm_id] = (++k == 5) ? 0 : k;
    atomic_add(delay, &device_time.delay[vm_id]);
    DEBUG_PRINT("vm#%d delay is updated to %d\n", vm_id, atomic_read(&device_time.delay[vm_id]));
    #endif
}

static struct resource_policy device_time_func = {
    .kvm_init = init_device_time,
    .kvm_release = NULL,

    .vm_init = NULL,
    .vm_release = NULL,
    .vm_check = check_vm_device_time,

    .app_init = init_app_device_time,
    .app_release = release_app_device_time,
};
EXPORT_SYMBOL_GPL(device_time_func);
