#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <string.h>
#include <stdarg.h>


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
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, long);
    __uint(max_entries, 65535);
} drop_to_ports SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, long);
    __uint(max_entries, 65535);
} drop_from_ports SEC(".maps");

struct ipport
{
    __u32 addr;
    __u16 port;
} ipport ;

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(ipport));
    __uint(value_size, sizeof(long));
    __uint(max_entries, 1024);
} drop_to_ipport SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(ipport));
    __uint(value_size, sizeof(long));
    __uint(max_entries, 1024);
} drop_from_ipport SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} event_report_area SEC(".maps");

typedef __u32 u32;
typedef __u8 u8;
typedef __u16 u16;

#define MAX_DNS_NAME_LENGTH 128

struct dnshdr
{
	uint16_t transaction_id;
	uint8_t rd : 1;		 // Recursion desired
	uint8_t tc : 1;		 // Truncated
	uint8_t aa : 1;		 // Authoritive answer
	uint8_t opcode : 4;	 // Opcode
	uint8_t qr : 1;		 // Query/response flag
	uint8_t rcode : 4;	 // Response code
	uint8_t cd : 1;		 // Checking disabled
	uint8_t ad : 1;		 // Authenticated data
	uint8_t z : 1;		 // Z reserved bit
	uint8_t ra : 1;		 // Recursion available
	uint16_t q_count;	 // Number of questions
	uint16_t ans_count;	 // Number of answer RRs
	uint16_t auth_count; // Number of authority RRs
	uint16_t add_count;	 // Number of resource RRs
};

struct dnsquery
{
	// char name[MAX_DNS_NAME_LENGTH];
	u8 name[MAX_DNS_NAME_LENGTH];
};

#define MAX_ENTRIES 1024
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, MAX_DNS_NAME_LENGTH);
	__uint(value_size, sizeof(long));
	__uint(max_entries, MAX_ENTRIES);
} drop_dns SEC(".maps");

static int parse_query(void *data_end, void *query_start, struct dnsquery *q)
{
	void *cursor = query_start;
	memset(&q->name[0], 0, sizeof(q->name));
	__u8 label_cursor = 0;

	// The loop starts with '-1', because the first char will be '.'
	// and we want to bypass it, check (i == -1) statement for details.
	for (__s16 i = -1; i < MAX_DNS_NAME_LENGTH; i++, cursor++)
	{
		if (cursor + 1 > data_end)
		{
			return -1; // packet is too short.
		}

		if (*(__u8 *)cursor == 0)
		{
			break; // end of domain name.
		}

		if (label_cursor == 0)
		{
			// the cursor is on a label length byte.
			__u8 new_label_length = *(__u8 *)cursor;
			if (cursor + new_label_length > data_end)
			{
				return -1; // packet is too short.
			}
			label_cursor = new_label_length;
			if (i == -1)
			{
				// This is the first label, no need to set '.'
				continue;
			}
			q->name[i] = '.';
			continue;
		}

		label_cursor--;
		char c = *(char *)cursor;
		q->name[i] = c;
	}

	return 1;
}


struct my_event
{
	u32 saddr;
	u16 sport;
	u32 daddr;
	u16 dport;
    struct dnsquery query;
};
const struct my_event *unused __attribute__((unused));

SEC("xdp_durdur_drop")
int xdp_durdur_drop_func(struct xdp_md *ctx)
{
	struct my_event *report;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    {
    		return XDP_PASS;
    }

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    		return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
	__u32 saddr = ip->daddr;
	__u16 sport = 0;
	__u32 daddr = ip->saddr;
	__u16 dport = 0;
	struct dnsquery query = {0};

	// Drop IP First
	{
        long *value;
        value = bpf_map_lookup_elem(&drop_to_addrs, &saddr);
	    if (value)
	    {
		    *value += 1;
		    goto DROPPER;
	    }

	    value = bpf_map_lookup_elem(&drop_from_addrs, &daddr);
	    if (value)
	    {
		    *value += 1;
		    goto DROPPER;
	    }
	}

	// Drop DNS Query
	if (ip->protocol == IPPROTO_UDP)
    	{
    		struct udphdr *udp;
    		if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
    		{
    			return XDP_PASS;
    		}

    		udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    		if (udp->source == bpf_htons(53))
    		{
    			if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(struct dnshdr) > data_end)
    			{
    				return XDP_PASS;
    			}

    			struct dnshdr *dns = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
    			if (dns->opcode == 0) // it's a dns query.
    			{
    				void *query_start = (void *)dns + sizeof(struct dnshdr);

    				struct dnsquery query;
    				if (!parse_query(data_end, query_start, &query))
    				{
    					return XDP_PASS;
    				}

    				long *pkt_count = bpf_map_lookup_elem(&drop_dns, &query.name);
    				if (pkt_count)
    				{
    					return XDP_DROP;
    				}
    			}
    		}
    	}

    // Drop TCP ports and ports + ip
    if (ip->protocol != IPPROTO_TCP) {
        long *value;
        struct tcphdr *tcp;
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        {
            return XDP_PASS;
        }
        tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        sport = tcp->source;
        dport = tcp->dest;
        struct ipport sipport = { saddr, sport };
        struct ipport dipport = { daddr, dport };

        value = bpf_map_lookup_elem(&drop_to_ports, &sport);
        if (value)
        {
            *value += 1;
            goto DROPPER;
        }

        value = bpf_map_lookup_elem(&drop_from_ports, &dport);
        if (value)
        {
            *value += 1;
            goto DROPPER;
        }

        value = bpf_map_lookup_elem(&drop_to_ipport, &sipport);
        if (value)
        {
            *value += 1;
            goto DROPPER;
        }

        value = bpf_map_lookup_elem(&drop_from_ipport, &dipport);
        if (value)
        {
            *value += 1;
            goto DROPPER;
        }

    }
	return XDP_PASS;

DROPPER:
	report = bpf_ringbuf_reserve(&event_report_area, sizeof(struct my_event), 0);
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
	report->query = query;
	bpf_ringbuf_submit(report, BPF_RB_FORCE_WAKEUP);
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
