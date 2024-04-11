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


// Attempt to parse the 5-tuple session identifier from the packet.
// Returns 0 if there is no IPv4 header field or if L4 is not a UDP, TCP or ICMP packet; otherwise returns non-zero.
static __always_inline int parse_session_identifier(void *data, void *data_end, tc_event *key) {
	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return 0;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		return 0;
	}

	// Then parse the IP header.
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return 0;
	}

	// Then parse the L4 header.
	switch (ip->protocol) {
	case IPPROTO_TCP: {
		// TCP protocol carried, parse TCP header.
		struct tcphdr *tcp = (void *)(ip + 1);
		if ((void *)(tcp + 1) > data_end)
			return 0;
		key->sport = (__u16)(tcp->source);
		key->dport = (__u16)(tcp->dest);
		break;
	}
	case IPPROTO_UDP: {
		// UDP protocol carried, parse TCP header.
		struct udphdr *udp = (void *)(ip + 1);
		if ((void *)(udp + 1) > data_end)
			return 0;
		key->sport = (__u16)(udp->source);
		key->dport = (__u16)(udp->dest);
		break;
	}
	case IPPROTO_ICMP: {
		// ICMP protocol carried, no source/dest port.
		break;
	}
	// Unchecked protocols, ignore them
	default: {
		return 0;
	}
	}

	// Fill session key with IP header data
	key->saddr = (__u32)(ip->saddr);
	key->daddr = (__u32)(ip->daddr);
	return 1;
}

SEC("tc_durdur_drop")
int tc_durdur_drop_func(struct __sk_buff *skb) {
	tc_event report = {};
	tc_event *report_addr;
	void* data = (void *)(long) skb->data;
	void* data_end = (void *)(long) skb->data_end;
    
	if (!parse_session_identifier(data, data_end, &report)) {
		return TC_ACT_OK;
	}

	long *value;
		value = bpf_map_lookup_elem(&drop_to_addrs, &report.daddr);
	    if (value)
	    {
		    *value += 1;
		    goto TC_DROP;
	    }
    
    struct ipport dipport = { report.daddr, report.dport };
        value = bpf_map_lookup_elem(&drop_to_ports, &report.dport);
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
	report_addr = bpf_ringbuf_reserve(&tc_event_report_area, sizeof(tc_event), 0);
	// bpf_printk("Reporting");
	if (!report_addr)
	{
		// bpf_printk("Report Error");
		return TC_ACT_SHOT;
	}
	report_addr->saddr = report.saddr;
	report_addr->sport = report.sport;
	report_addr->daddr = report.daddr;
	report_addr->dport = report.dport;
	bpf_ringbuf_submit(report_addr, BPF_RB_FORCE_WAKEUP);
	return TC_ACT_SHOT;
}