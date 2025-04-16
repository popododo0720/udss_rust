#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

// clang -O2 -g -target bpf -c filter.c -o filter.o

// 사용자로 보낼 Perf Event Array 맵
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024); 
} perf_output SEC(".maps");

// 패킷 메타데이터 담을 구조체
struct packet_info {
    __u8 src_mac[6];  
    __u8 dst_mac[6]; 
    __u16 vlan_tci;
    __u16 vlan_encapsulated_proto;
    __u16 ip_id;
    __u32 src_ip; 
    __u32 dst_ip; 
    __u16 src_port;
    __u16 dst_port;
    __u16 dns_tr_id;
    __u8 dns_query[50];
};

struct vlan_hdr {
    __u16 h_vlan_TCI;                // VLAN ID + Priority + CFI (16비트)
    __u16 h_vlan_encapsulated_proto; // VLAN 다음 프로토콜
};

struct dns_hdr {
    __u16 transaction_id;
    __u16 flags;
    __u16 questions;
    __u16 answer_rrs;
    __u16 authority_rrs;
    __u16 additional_rrs;
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
        return XDP_DROP;
    }

    struct vlan_hdr *vhdr = NULL;
    __u16 eth_proto = eth->h_proto;
    void *next_header = (void *)(eth + 1);
    __u16 vlan_tci = 0;
    __u16 vlan_proto = ETH_P_IP;  // 기본값 설정

    // VLAN 태그 확인 후 처리
    if( eth_proto == __constant_htons(ETH_P_8021Q) ) {
        vhdr = (struct vlan_hdr *)next_header;
        if ((void *)(vhdr + 1) > data_end) {
            return XDP_DROP;
        }
        vlan_tci = vhdr->h_vlan_TCI;
        vlan_proto = vhdr->h_vlan_encapsulated_proto;
        eth_proto = vlan_proto;
        next_header = (void *)(vhdr + 1);
    } else if( eth_proto == __constant_htons(ETH_P_IP) ) {
    }
    else {
        return XDP_DROP;
    }

    // ip header
    struct iphdr *iph = next_header;
    if( (void *)(iph + 1) > data_end ) {
        return XDP_DROP;
    }

    // UDP
    if( iph->protocol != IPPROTO_UDP) {
        return XDP_DROP;
    }

    // udp header
    struct udphdr *udph = (struct udphdr *)((__u8 *)iph + (iph->ihl * 4));
    if ( (void *)(udph + 1) > data_end ) {
        return XDP_DROP;
    }

    struct dns_hdr *dnsh = (struct dns_hdr *)((void *)udph + sizeof(struct udphdr));
    if ((void *)(dnsh + 1) > data_end) {
        return XDP_DROP;
    }

    __u16 dns_flags = dnsh->flags;
    __u8 qr_bit = dns_flags >> 15;
    if( qr_bit != 0 ) {
        return XDP_DROP;
    }

    __u8 *dns_query_start = (__u8 *)dnsh + sizeof(struct dns_hdr);
    if ((void *)(dns_query_start + 1) > data_end) {
        return XDP_DROP;
    }

    // char domain[50] = {0};  
    // __u8 *ptr = dns_query_start;
    // int offset = 0;

    // while (*ptr != 0 && (void *)(ptr + 1) <= data_end) {
    //     int len = *ptr;  
    //     if (offset + len >= 50) break; 

    //     ptr++;  
    //     for (int i = 0; i < len; i++) {
    //         domain[offset++] = *ptr++;
    //     }

    //     domain[offset++] = '.';  
    // }

    // if (offset > 0) domain[offset - 1] = '\0';

    // dst port
    if( udph->dest == __constant_htons(53) ) {
        struct packet_info info = {};
        for (int i = 0; i < 6; i++) {
            info.src_mac[i] = eth->h_source[i];
            info.dst_mac[i] = eth->h_dest[i];
        }   
        
        info.vlan_tci = vlan_tci;
        info.vlan_encapsulated_proto = vlan_proto;

        info.ip_id = iph->id;

        info.src_ip = iph->saddr;
        info.dst_ip = iph->daddr;

        info.src_port = udph->source;
        info.dst_port = udph->dest;

        info.dns_tr_id = dnsh->transaction_id;

        long status = bpf_perf_event_output(ctx, &perf_output, BPF_F_CURRENT_CPU, &info, sizeof(info));
        if( status != 0 ) {
            bpf_printk("Failed to submit perf event: %d\n", status);
        }
        return XDP_PASS;
    }
    return XDP_DROP;
}