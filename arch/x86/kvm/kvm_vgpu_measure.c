#include <linux/kernel.h>
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/timer.h>
#include <linux/hrtimer.h>

#include <scea/common/devconf.h>
#include <scea/kvm.h>

/* command rate measurement */
static struct command_rate_measure {
    struct timer_list timer;
    atomic_t count[MAX_VM_NUM + 1];
} command_rate_measure;

static void command_rate_measure_timer_callback(unsigned long data)
{
    int i;

    for (i = 1; i <= MAX_VM_NUM; i++)
        if (vgpu_dev->vm_ids[i]) {
            trace_printk("[interval=%d ms] vm#%d command rate count = %u\n",
                         COMMAND_RATE_MEASURE_PERIOD,
                         i, atomic_read(&command_rate_measure.count[i]));
            atomic_set(&command_rate_measure.count[i], 0);
        }

    mod_timer(&command_rate_measure.timer, jiffies + msecs_to_jiffies(COMMAND_RATE_MEASURE_PERIOD));
}

void init_command_rate_measure(void)
{
    int i;
    for (i = 1; i <= MAX_VM_NUM; i++)
        atomic_set(&command_rate_measure.count[i], 0);

    /* start periodic timer */
    setup_timer(&command_rate_measure.timer, command_rate_measure_timer_callback, 0);
    mod_timer(&command_rate_measure.timer, jiffies + msecs_to_jiffies(COMMAND_RATE_MEASURE_PERIOD));
}

void count_command_rate_measure(int vm_id, int consumed)
{
    atomic_add(consumed, &command_rate_measure.count[vm_id]);
}

/* device time measurement */
static struct device_time_measure {
    struct hrtimer timer;
    atomic64_t time[MAX_VM_NUM + 1];
} device_time_measure;

static enum hrtimer_restart device_time_measure_timer_callback(struct hrtimer *timer)
{
    int i;

    for (i = 1; i <= MAX_VM_NUM; i++)
        if (vgpu_dev->vm_ids[i]) {
            trace_printk("[interval=%d ms] vm#%d consumed device time = %lu us\n",
                         DEVICE_TIME_MEASURE_PERIOD,
                         i, atomic64_xchg(&device_time_measure.time[i], 0));
        }

    hrtimer_forward(timer, hrtimer_cb_get_time(timer), ktime_set(0, DEVICE_TIME_MEASURE_PERIOD * NSEC_PER_MSEC));

    return HRTIMER_RESTART;
}

void init_device_time_measure(void)
{
    int i;
    ktime_t kt;

    for (i = 1; i <= MAX_VM_NUM; i++)
        atomic64_set(&device_time_measure.time[i], 0);

    /* start periodic timer */
    hrtimer_init(&device_time_measure.timer, CLOCK_REALTIME, HRTIMER_MODE_ABS);
    kt = ktime_set(0, DEVICE_TIME_MEASURE_PERIOD * NSEC_PER_MSEC);
    device_time_measure.timer.function = &device_time_measure_timer_callback;
    hrtimer_start(&device_time_measure.timer, kt, HRTIMER_MODE_ABS);

    trace_printk("Initialize device time with HRTIMER\n");
}

void count_device_time_measure(int vm_id, long consumed)
{
    atomic64_add(consumed, &device_time_measure.time[vm_id]);
}

void fini_device_time_measure(void)
{
    int r;
    r = hrtimer_cancel(&device_time_measure.timer);
    BUG_ON(r != 0 && r != 1);
}
