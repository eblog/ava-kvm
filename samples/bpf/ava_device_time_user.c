// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <assert.h>
#include <linux/bpf.h>
#include "libbpf.h"
#include "bpf_load.h"
#include <unistd.h>
#include <fcntl.h>

#include <../../include/scea/common/devconf.h>
#include <../../include/scea/common/ioctl.h>
#include <../../include/scea/common/bpf.h>

int main(int ac, char **argv)
{
	char filename[256];
	int kvm_fd;
    int policy_id;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}

    assert((kvm_fd = open("/dev/kvm-vgpu", O_RDWR | O_NONBLOCK)) > 0);
    assert((policy_id = ioctl(kvm_fd, KVM_ATTACH_BPF, prog_fd)) > 0);

    /* set priorities */
    int vm_id;
    int priority;
    for (vm_id = 1; vm_id <= MAX_VM_NUM; vm_id++) {
        priority = PREDEFINED_RATE_SHARES[vm_id];
        assert(bpf_map_update_elem(map_fd[1], &vm_id, &priority, BPF_EXIST) == 0);
        printf("[%d] priority set to=%d\n", vm_id, priority);
    }

    sleep(300);
    long long command_num;
    for (vm_id = 0; vm_id <= MAX_VM_NUM; vm_id++) {
        assert(bpf_map_lookup_elem(map_fd[0], &vm_id, &command_num) == 0);
        printf("[%d] command number=%lld\n", vm_id, command_num);
    }

    assert(ioctl(kvm_fd, KVM_DETACH_BPF, policy_id) == 0);
    close(kvm_fd);
	return 0;
}
