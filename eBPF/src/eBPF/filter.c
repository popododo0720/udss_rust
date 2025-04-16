#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>


// 사용자로 보낼 Perf Event Array 맵
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024); 
} perf_output SEC(".maps");

// 패킷 메타데이터 담을 구조체
struct packet_info {
    __u32 src_ip; // IPv4 소스 주소
};

// 라이선스 
char LICENSE[] SEC("license") = "GPL";

// XDP
SEC("xdp") 
int xdp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // ethernet header
    struct ethhdr *eth = data;
    if( (void *)(eth + 1) > data_end ) {
        return XDP_PASS;
    }

    // ipv4
    if( eth->h_proto != __constant_htons(ETH_P_IP) ) {
        return XDP_PASS;
    }

    // ip header
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if( (void *)(iph + 1) > data_end ) {
        return XDP_PASS;
    }

    // UDP
    if( iph->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    // udp header
    struct udphdr *udph = (struct udphdr *)((__u8 *)iph + (iph->ihl * 4));
    if ( (void *)(udph + 1) > data_end ) {
        return XDP_PASS;
    }

    // dst port
    if( udph->dest == __constant_htons(53) ) {
        struct packet_info info = {};
        info.src_ip = iph->saddr;

        long status = bpf_perf_event_output(ctx, &perf_output, BPF_F_CURRENT_CPU, &info, sizeof(info));
        if( status != 0 ) {
            bpf_printk("Failed to submit perf event: %d\n", status);
        }
        return XDP_PASS;
    }
    return XDP_PASS;
}