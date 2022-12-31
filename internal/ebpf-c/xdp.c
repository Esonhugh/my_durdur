#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, long);
	__uint(max_entries, 1024);
} drop_to_addrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, long);
	__uint(max_entries, 1024);
} drop_from_addrs SEC(".maps");


typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;


struct 
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} event_report_area SEC(".maps");

struct event {
	u32 addr;
	u8 direction; // == 1 saddr == 2 daddr
};
// struct event *unused_event __attribute__((unused));

SEC("xdp_durdur_drop")
int xdp_durdur_drop_func(struct xdp_md* ctx)
{
	void* data_end = (void*)(long)ctx->data_end;
	void* data = (void*)(long)ctx->data;
	struct ethhdr* eth = data;
	long* value;

	uint64_t nh_off = sizeof(*eth);
	if (data + nh_off > data_end) {
		return XDP_PASS;
	}
	
	struct iphdr* iph = data + nh_off;
	struct udphdr* udph = data + nh_off + sizeof(struct iphdr);
	if (udph + 1 > (struct udphdr*)data_end) {
		return XDP_PASS;
	}

	u8 direct;
	__u32 addr = iph->daddr;
	value = bpf_map_lookup_elem(&drop_to_addrs, &addr);
	if (value) {
		*value += 1;
		direct = 1;
	
	struct event *report;
	report = bpf_ringbuf_reserve(&event_report_area, sizeof(struct event), 0);
	if (!report) {
		return XDP_DROP;
	}
	report->addr = addr;
	report->direction = direct;
	bpf_ringbuf_submit(report, 0);
	return XDP_DROP;

		// goto drop;
	}

	addr = iph->saddr;
	value = bpf_map_lookup_elem(&drop_from_addrs, &addr);
	if (value) {
		*value += 1;
		direct = 2;
	
	struct event *report;
	report = bpf_ringbuf_reserve(&event_report_area, sizeof(struct event), 0);
	if (!report) {
		return XDP_DROP;
	}
	report->addr = addr;
	report->direction = direct;
	bpf_ringbuf_submit(report, 0);
	return XDP_DROP;
		// goto DROPPER;
	}

	return XDP_PASS;

/*
	DROPPER: struct event *report;
	report = bpf_ringbuf_reserve(&event_report_area, sizeof(struct event), 0);
	if (!report) {
		return XDP_DROP;
	}
	report->addr = addr;
	report->direction = direct;
	bpf_ringbuf_submit(report, 0);
	return XDP_DROP;
*/
}

char _license[] SEC("license") = "GPL";
