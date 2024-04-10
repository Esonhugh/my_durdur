#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <linux/swab.h>

#include <string.h>
#include <stdarg.h>

#include "include/common_define.h"

typedef struct ipport tc_ipport;
UNUSED(tc_ipport);
typedef struct report_event tc_event;
UNUSED(tc_event);
//const tc_event *unused __attribute__((unused));


struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, long);
	__uint(max_entries, 1024);
} drop_to_addrs SEC(".maps");
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, long);
    __uint(max_entries, 65535);
} drop_to_ports SEC(".maps");
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(tc_ipport));
    __uint(value_size, sizeof(long));
    __uint(max_entries, 1024);
} drop_to_ipport SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} tc_event_report_area SEC(".maps");

SEC("tc_durdur_drop")
int tc_durdur_drop_func(struct __sk_buff *skb) {
	tc_event *report;
	void* data = (void *)(long) skb->data;
	void* data_end = (void *)(long) skb->data_end;

    if (data + sizeof(struct ethhdr) > data_end) {
        return TC_ACT_SHOT;
	}

	struct ethhdr *eth = data;
	if (eth->h_proto !=  bpf_htons(ETH_P_IP)) {
		return TC_ACT_OK;
	}

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return TC_ACT_OK;
    }
	// on Egress
    struct iphdr *ip = data + sizeof(struct ethhdr);
	__u32 saddr = ip->daddr;
	__u16 sport = 0;
	__u32 daddr = ip->saddr;
	__u16 dport = 0;
    
    long *value;
    struct tcphdr *tcp;
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
    {
            return TC_ACT_OK;
    }
    tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    sport = tcp->source;
    dport = tcp->dest;
    // struct ipport sipport = { saddr, sport };
    struct ipport dipport = { daddr, dport };
        
		value = bpf_map_lookup_elem(&drop_to_addrs, &daddr);
	    if (value)
	    {
		    *value += 1;
		    goto TC_DROP;
	    }
        value = bpf_map_lookup_elem(&drop_to_ports, &dport);
        if (value)
        {
            *value += 1;
            goto TC_DROP;
        }
        value = bpf_map_lookup_elem(&drop_to_ipport, &dipport);
        if (value)
        {
            *value += 1;
            goto TC_DROP;
        }

	// not match don't drop
	return TC_ACT_OK;
	
TC_DROP:
	report = bpf_ringbuf_reserve(&tc_event_report_area, sizeof(tc_event), 0);
	// bpf_printk("Reporting");
	if (!report)
	{
		// bpf_printk("Report Error");
		return TC_ACT_SHOT;
	}
	report->saddr = saddr;
	report->sport = sport;
	report->daddr = daddr;
	report->dport = dport;
	bpf_ringbuf_submit(report, BPF_RB_FORCE_WAKEUP);
	return TC_ACT_SHOT;
}