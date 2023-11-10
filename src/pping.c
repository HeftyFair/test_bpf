#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include "parse.h"


char LICENSE[] SEC("license") = "GPL";


struct packet_id {
    unsigned int id;
};


// Map definitions
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct packet_id);
	__type(value, __u64);
	__uint(max_entries, 100);
} packet_ts SEC(".maps");




SEC("xdp")
int xdp_parse(struct xdp_md *md)
{
	struct hdr_cursor nh;
	struct iphdr *iph;
	struct udphdr *udph;
	struct ipv6hdr *ip6h;
	struct ethhdr *eth;
	__u64 timestamp;
	unsigned short _proto;
	struct packet_id pkt_id;
	int myid;
	int proto;
	void *data_end = (void *)(long)md->data_end;
    void *data = (void *)(long)md->data;
	nh.pos = data;
	proto = parse_ethhdr(&nh, data_end, &eth);
	
	if (proto == bpf_htons(ETH_P_IP)) {
		
		_proto = parse_iphdr(&nh, data_end, &iph);
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
	
		_proto = parse_ip6hdr(&nh, data_end, &ip6h);
	} else {
		return XDP_PASS;
	}
	__uint32_t *arr;
	//parse_iphdr(&nh, md->data_end, &ip);
	if (_proto == IPPROTO_UDP) {
		if (parse_udphdr(&nh, data_end, &udph) < 0) {
			goto pass;
		}
	
		if (udph->source == bpf_htons(443)) {
			timestamp = bpf_ktime_get_ns();
			pkt_id.id = bpf_ntohl(iph->saddr);
			
			if (data_end < nh.pos + 8)
				goto pass;
			//arr = (__uint32_t *)nh.pos;
			__u32 *arr = (__u32 *)(udph + 1);
			bpf_printk("conn id: %08x\n", arr[1]);
			bpf_printk("conn id: %08x\n", arr[0]);
			bpf_printk("QUIC packet received\n");
			//iph->daddr = bpf_htonl(0x0a000001);
			//iph->saddr = bpf_htonl(0x0a000001);
			//myid = 1;
			bpf_map_update_elem(&packet_ts, &pkt_id, &timestamp, BPF_ANY);
		// Packet is using QUIC protocol
		}
	}

pass:
	return XDP_PASS;
}