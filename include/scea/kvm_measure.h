#ifndef __KVM_VGPU_MEASURE_H__
#define __KVM_VGPU_MEASURE_H__

#include <scea/common/devconf.h>

#ifdef ENABLE_MEASURE
#define AVA_MEASURE(function, ...) (function)(__VA_ARGS__)
#else
#define AVA_MEASURE(function, ...) {}
#endif

void init_command_rate_measure(void);
void count_command_rate_measure(int vm_id, int consumed);

void init_device_time_measure(void);
void count_device_time_measure(int vm_id, long consumed);

#endif
