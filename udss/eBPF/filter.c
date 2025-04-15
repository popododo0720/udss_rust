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