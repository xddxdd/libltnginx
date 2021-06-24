#include "../src/whois/whois.h"
#include <stdio.h>

int main() {
    whois_ip_init();

    printf("\nIP\n");
    printf("%s\n", whois_ip_lookup("8.8.8.8"));
    printf("%s\n", whois_ip_lookup("114.114.114.114"));
    printf("%s\n", whois_ip_lookup("2001:4860:4860::8888"));
    printf("%s\n", whois_ip_lookup("240c::6666"));

    printf("\nNIC Handle\n");
    printf("%s\n", whois_nic_handle_lookup("STREXP-MNT"));
    printf("%s\n", whois_nic_handle_lookup("STREXP-TEL"));
    printf("%s\n", whois_nic_handle_lookup("STREXP-RIPE"));
    printf("%s\n", whois_nic_handle_lookup("STREXP-HELLO"));

    printf("\nDomain\n");
    printf("%s\n", whois_domain_lookup("lantian.pub"));
    printf("%s\n", whois_domain_lookup("google.com"));
    printf("%s\n", whois_domain_lookup("www.gov.cn"));
    printf("%s\n", whois_domain_lookup("mirrors.ustc.edu.cn"));

    printf("\nASN\n");
    printf("%s\n", whois_asn_lookup(174));
    printf("%s\n", whois_asn_lookup(61950));
    printf("%s\n", whois_asn_lookup(4242422547));

    return 0;
}
