#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} blocked_net SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);  // eski BPF_MAP_PERCPU_ARRAY değil
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_cnt SEC(".maps");

SEC("xdp")
int block_icmp(struct xdp_md *ctx)
{
void *data = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;

struct ethhdr *eth = data;
__u16 h_proto = eth->h_proto;

if ((void*)(eth + 1) > data_end)
    return XDP_PASS;

if(h_proto == __constant_htons(ETH_P_IP)){
	struct iphdr *iph = data+ sizeof(struct ethhdr);
	if ((void*)(iph + 1) > data_end)
	    return XDP_PASS;
__u32 src_ip = __builtin_bswap32(iph->saddr);
__u32 key = 0;
__u32 *net = bpf_map_lookup_elem(&blocked_net, &key);

if (!net)
    return XDP_PASS;   // map boşsa paketi geçir
	if (src_ip == *net && iph->protocol == IPPROTO_ICMP) {
	__u32 key = 0;
	__u64 *value = bpf_map_lookup_elem(&drop_cnt,&key);
	if(value){
	__sync_fetch_and_add(value,1);
}
	    return XDP_DROP;
	}

}
 return XDP_PASS;


}

char _license[] SEC("license") = "GPL";
