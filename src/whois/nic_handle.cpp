#include <unordered_map>
#include <string>
#include <cstring>
#include <algorithm>
#include "whois.h"

std::unordered_map<std::string, const char*> map_nic_handle = {
    {"-arin", "whois.arin.net"},
    {"-ripe", "whois.ripe.net"},
    {"-mnt", "whois.ripe.net"},
    {"-lacnic", "whois.lacnic.net"},
    {"-afrinic", "whois.afrinic.net"},
    {"-ap", "whois.apnic.net"},
    {"-cznic", "whois.nic.cz"},
    {"-dk", "whois.dk-hostmaster.dk"},
    {"-il", "whois.isoc.org.il"},
    {"-is", "whois.isnic.is"},
    {"-kg", "whois.domain.kg"},
    {"-coop", "whois.nic.coop"},
    {"-frnic", "whois.nic.fr"},
    {"-lrms", "whois.afilias.info"},
    {"-metu", "whois.nic.tr"},
    {"-nicat", "whois.nic.at"},
    {"-nicci", "whois.nic.ci"},
    {"-irnic", "whois.nic.ir"},
    {"-norid", "whois.norid.no"},
    {"-tel", "whois.nic.tel"},
    {"-adnic", "whois.nic.org.uy"},
    {"-sixxs", "whois.sixxs.net"},
    {"-uanic", "whois.ua"},
    {"-bzh", "whois.nic.bzh"},
};

extern "C" const char* whois_nic_handle_lookup(char* name) {
    char* ch = std::strrchr(name, '-');
    if (ch == NULL) {
        return WHOIS_FALLBACK;
    }

    std::string s(ch);
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);

    auto it = map_nic_handle.find(s);
    if (it != map_nic_handle.end()) {
        return it->second;
    }

    return WHOIS_FALLBACK;
}
