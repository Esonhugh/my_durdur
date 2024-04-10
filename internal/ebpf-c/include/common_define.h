#include <asm/types.h>

#ifndef __COMMON_STRUCT
#define __COMMON_STRUCT

#define UNUSED_STRUCT(x) const struct x UNUSED_ ## x __attribute__((__unused__))
#define UNUSED(x) const x UNUSED_ ## x __attribute__((unused))

struct ipport
{
    __u32 addr;
    __u16 port;
};
UNUSED_STRUCT(ipport);
//const struct ipport *unused_ipport __attribute__((unused));

struct report_event
{
	__u32 saddr;
	__u16 sport;
	__u32 daddr;
	__u16 dport;
};
UNUSED_STRUCT(report_event);
//const struct report_event *unused __attribute__((unused));

#endif