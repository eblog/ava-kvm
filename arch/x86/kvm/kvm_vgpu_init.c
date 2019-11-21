#include <scea/common/devconf.h>
#include <scea/kvm.h>

void init_vm_info(struct vm_info *vm_info) {
    memset(vm_info, 0, sizeof(struct vm_info));
    INIT_LIST_HEAD(&vm_info->app_info_list.list);
}

void destroy_vm_info(struct vm_info *vm_info) {
    kfree(vm_info);
}

void init_app_info(struct app_info *app_info,
                   u64 guest_cid, u32 app_port, u32 worker_port,
                   struct vm_info *vm_info) {
    struct netlink_info *nl_pos, *nl_n;
    int num_tries = 0;

    app_info->app_cid = guest_cid;
    app_info->app_port = app_port;
    app_info->worker_port = worker_port;
    app_info->vm_id = vm_info->vm_id;
    app_info->vm_info = vm_info;
    list_add(&app_info->list, &vm_info->app_info_list.list);

    /* look for netlink info */
    app_info->nl_info = NULL;
lookup_nlinfo:
    num_tries++;
    list_for_each_entry_safe(nl_pos, nl_n, &vgpu_dev->netlink_info_list.list, list)
        if (nl_pos->worker_port == worker_port) {
            app_info->worker_pid = nl_pos->worker_pid;
            app_info->nl_info = nl_pos;
            nl_pos->vm_id = app_info->vm_id;
            hash_add(vgpu_dev->worker_hash, &nl_pos->node, nl_pos->worker_pid);
            list_del(&nl_pos->list);
            break;
        }

    // TODO: use wakeup event
    if (num_tries < 20 && !app_info->nl_info) {
        DEBUG_PRINT("netlink_info for worker@%d not found\n", worker_port);
        msleep(100);
        goto lookup_nlinfo;
    }
}

void destroy_app_info(struct app_info *app_info) {
    list_del(&app_info->list);
    if (app_info->nl_info) {
        hash_del(&app_info->nl_info->node);
        kfree(app_info->nl_info);
    }
    kfree(app_info);
}

void init_nl_info(struct netlink_info *nl_info,
                  int vm_id, int worker_port, int worker_pid) {
    DEBUG_PRINT("register netlink for worker[%d]@%d\n", worker_pid, worker_port);
    nl_info->vm_id = vm_id;
    nl_info->worker_port = worker_port;
    nl_info->worker_pid = worker_pid;
    list_add(&nl_info->list, &vgpu_dev->netlink_info_list.list);
}
