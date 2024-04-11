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

typedef struct ipport xdp_ipport;
UNUSED(xdp_ipport);
// const xdp_ipport *unused_ipport __attribute__((unused)); // to suppress warning for
typedef struct report_event xdp_event;
UNUSED(xdp_event);
// const xdp_event *unused_event __attribute__((unused)); // to suppress warning for

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, long);
	__uint(max_entries, 1024);
} drop_from_addrs SEC(".maps");
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u16);
	__type(value, long);
	__uint(max_entries, 65535);
} drop_from_ports SEC(".maps");
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(xdp_ipport));
	__uint(value_size, sizeof(long));
	__uint(max_entries, 1024);
} drop_from_ipport SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} xdp_event_report_area SEC(".maps");

SEC("xdp_durdur_dpop") // Ingress
int xdp_durdur_drop_func(struct xdp_md *ctx)
{
	xdp_event *report;
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(struct ethhdr) > data_end)
	{
		return XDP_PASS;
	}
	// not ip packet
	struct ethhdr *eth = data;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
	{
		return XDP_PASS;
	}
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
	{
		return XDP_PASS;
	}

	struct iphdr *ip = data + sizeof(struct ethhdr);
	__u32 saddr = ip->saddr;
	__u16 sport = 0;
	__u32 daddr = ip->daddr;
	__u16 dport = 0;

	// Drop IP First
	{
		long *value;
		value = bpf_map_lookup_elem(&drop_from_addrs, &saddr);
		if (value)
		{
			*value += 1;
			goto DROPPER;
		}
	}
	// Drop TCP ports and ports + ip
	{
		switch (ip->protocol)
		{
		case IPPROTO_UDP:
			if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
			{
				return XDP_PASS;
			}
			struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
			sport = udp->source;
			dport = udp->dest;
			/* code */
			break;
		case IPPROTO_TCP:
			if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
			{
				return XDP_PASS;
			}
			struct tcphdr *tcp;
			tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
			sport = tcp->source;
			dport = tcp->dest;
			break;
		default:
			break;
		}
		long *value;
		value = bpf_map_lookup_elem(&drop_from_ports, &dport);
		if (value)
		{
			*value += 1;
			goto DROPPER;
		}
		struct ipport sipport = {saddr, dport};
		// struct ipport dipport = { daddr, dport };
		value = bpf_map_lookup_elem(&drop_from_ipport, &sipport);
		if (value)
		{
			*value += 1;
			goto DROPPER;
		}
	}
	return XDP_PASS;

DROPPER:
	report = bpf_ringbuf_reserve(&xdp_event_report_area, sizeof(xdp_event), 0);
	// bpf_printk("Reporting");
	if (!report)
	{
		// bpf_printk("Report Error");
		return XDP_DROP;
	}
	report->saddr = saddr;
	report->sport = sport;
	report->daddr = daddr;
	report->dport = dport;

	bpf_ringbuf_submit(report, BPF_RB_FORCE_WAKEUP);
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
