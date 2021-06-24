#pragma once

#include <stdint.h>

#define WHOIS_FALLBACK "whois.arin.net"

#ifdef __cplusplus
extern "C" {
#endif

void whois_ip_init(void);
char* whois_ip_lookup(char* cidr);
const char* whois_nic_handle_lookup(char* name);
const char* whois_domain_lookup(char* name);
const char* whois_asn_lookup(uint32_t asn);

#ifdef __cplusplus
};
#endif
