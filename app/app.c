#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    int ifindex, prog_fd;
    int map_fd;
    __u32 key, next_key;
    __u64 value;


    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ifindex> <filename.o>\n", argv[0]);
        return 1;
    }
    
    ifindex = atoi(argv[1]);
    //printf("%s", argv[2]);
    obj = bpf_object__open(argv[2]);
    //printf("no");
    if (libbpf_get_error(obj)) {
        printf("Failed to open BPF object\n");
        return 1;
    }
    if (bpf_object__load(obj)) {
        printf("Failed to load BPF object\n");
        return 1;
    }

    

    prog = bpf_object__find_program_by_name(obj, "xdp_parse");
    if (!prog) {
        fprintf(stderr, "Failed to find XDP program 'xdp_parse'\n");
        return 1;
    }

    prog_fd = bpf_program__fd(prog);
    if (bpf_set_link_xdp_fd(ifindex, prog_fd, 0) < 0) {
        fprintf(stderr, "Failed to attach XDP program to interface %d\n", ifindex);
        return 1;
    }
    printf("Successfully attached XDP program to interface %d\n", ifindex);
    key = UINT32_MAX;
    map_fd = bpf_object__find_map_fd_by_name(obj, "packet_ts");
    if (map_fd < 0) {
        printf("Failed to get map FD\n");
        return 1;
    }

    while (1) {
        while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
                printf("Key: %u, Value: %llu\n", next_key, value);
            } else {
                fprintf(stderr, "Failed to lookup value: %s\n", strerror(errno));
            }
            key = next_key;
        }
    }

    return 0;
}
