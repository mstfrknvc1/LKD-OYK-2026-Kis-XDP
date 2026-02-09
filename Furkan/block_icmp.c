#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

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
	if (iph->protocol == IPPROTO_ICMP) {
	    return XDP_DROP;
	}
}
 return XDP_PASS;


}

char _license[] SEC("license") = "GPL";
