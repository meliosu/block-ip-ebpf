#include <arpa/inet.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include "firewall.skel.h"

int find_map() {
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("wrong usage\n");
        return 1;
    }

    struct firewall_bpf *object = firewall_bpf__open();

    if (!object) {
        printf("error opening skeleton\n");
        return 1;
    }

    struct xdp_program *program = xdp_program__from_bpf_obj(object->obj, "xdp");

    if (!program) {
        printf("error creating xdp program from object\n");
        return 1;
    }

    if (!strcmp(argv[1], "attach")) {
        int if_index = if_nametoindex(argv[2]);

        if (if_index == 0) {
            printf("unknown interface: %s\n", argv[2]);
            return 1;
        }

        if (xdp_program__attach(program, if_index, XDP_MODE_SKB, 0) < 0) {
            printf("error attaching to interface\n");
            return 1;
        }
    } else if (!strcmp(argv[1], "detach")) {
        int if_index = if_nametoindex(argv[2]);

        if (if_index == 0) {
            printf("unknown interface: %s\n", argv[2]);
            return 1;
        }

        if (xdp_program__detach(program, if_index, XDP_MODE_NATIVE, 0) < 0) {
            printf("error detaching from interface\n");
            return 1;
        }
    } else if (!strcmp(argv[1], "allow")) {
        struct in_addr addr;

        if (inet_aton(argv[2], &addr) < 0) {
            printf("%s is not an ipv4 address\n", argv[2]);
            return 1;
        }

        struct bpf_map *blocklist = object->maps.blocklist;

        int map_fd = bpf_obj_get("/sys/fs/bpf/blocklist");

        if (bpf_map__reuse_fd(blocklist, map_fd) < 0) {
            printf("bpf_map__reuse_fd\n");
            return 1;
        }

        if (bpf_map__delete_elem(blocklist, &addr.s_addr, sizeof(addr.s_addr),
                                 BPF_ANY) < 0) {
            printf("error allowing ipv4 address\n");
            return 1;
        }
    } else if (!strcmp(argv[1], "deny")) {
        struct in_addr addr;

        if (inet_aton(argv[2], &addr) < 0) {
            printf("%s is not an ipv4 address\n", argv[2]);
            return 1;
        }

        struct bpf_map *blocklist = object->maps.blocklist;

        int map_fd = bpf_obj_get("/sys/fs/bpf/blocklist");

        if (bpf_map__reuse_fd(blocklist, map_fd) < 0) {
            printf("bpf_map__reuse_fd\n");
            return 1;
        }

        int value = 0;

        int err =
            bpf_map__update_elem(blocklist, &addr.s_addr, sizeof(addr.s_addr),
                                 &value, sizeof(value), BPF_ANY);
        if (err < 0) {
            printf("error denying ipv4 address\n");
            return 1;
        }
    } else {
        printf("incorrect usage\n");
        return 1;
    }

    return 0;
}
