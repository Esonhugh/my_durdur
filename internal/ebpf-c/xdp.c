#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>

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
	__type(key, __u32);
	__type(value, long);
	__uint(max_entries, 1024);
} drop_from_addrs SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} event_report_area SEC(".maps");

typedef __u32 u32;
typedef __u8 u8;

struct my_event
{
	u32 addr;
	u8 direction;
}; 
const struct my_event *unused __attribute__((unused));

SEC("xdp_durdur_drop")
int xdp_durdur_drop_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	long *value;
	struct my_event *report;

	uint64_t nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
	{
		return XDP_PASS;
	}

	struct iphdr *iph = data + nh_off;
	struct udphdr *udph = data + nh_off + sizeof(struct iphdr);
	if (udph + 1 > (struct udphdr *)data_end)
	{
		return XDP_PASS;
	}

	__u16 direct;
	__u32 addr = iph->daddr;
	value = bpf_map_lookup_elem(&drop_to_addrs, &addr);
	if (value)
	{
		*value += 1;
		direct = (u8)0;
		goto DROPPER;
	}

	addr = iph->saddr;
	value = bpf_map_lookup_elem(&drop_from_addrs, &addr);
	if (value)
	{
		*value += 1;
		direct = (u8)(1) ;
		goto DROPPER;
	}

	return XDP_PASS;

DROPPER:
	report = bpf_ringbuf_reserve(&event_report_area, sizeof(struct my_event), 0);
	if (!report)
	{
		return XDP_DROP;
	}
	report->addr = addr;
	report->direction = direct;
	bpf_ringbuf_submit(report, 0);
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
