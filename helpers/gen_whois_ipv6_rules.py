as_list = [
('2001:0000::', '32', 'whois.teredo.net'),
('2001:0200::', '23', 'whois.apnic.net'),
('2001:0400::', '23', 'whois.arin.net'),
('2001:0600::', '23', 'whois.ripe.net'),
('2001:0800::', '22', 'whois.ripe.net'),
('2001:0C00::', '22', 'whois.apnic.net'),
('2001:1000::', '22', 'whois.lacnic.net'),
('2001:1400::', '22', 'whois.ripe.net'),
('2001:1800::', '23', 'whois.arin.net'),
('2001:1A00::', '23', 'whois.ripe.net'),
('2001:1C00::', '22', 'whois.ripe.net'),
('2001:2000::', '19', 'whois.ripe.net'),
('2001:4000::', '23', 'whois.ripe.net'),
('2001:4200::', '23', 'whois.afrinic.net'),
('2001:4400::', '23', 'whois.apnic.net'),
('2001:4600::', '23', 'whois.ripe.net'),
('2001:4800::', '23', 'whois.arin.net'),
('2001:4A00::', '23', 'whois.ripe.net'),
('2001:4C00::', '22', 'whois.ripe.net'),
('2001:5000::', '20', 'whois.ripe.net'),
('2001:8000::', '18', 'whois.apnic.net'),
('2002:0000::', '16', 'whois.6to4.net'),
('2003:0000::', '18', 'whois.ripe.net'),
('2400:0000::', '20', 'whois.nic.or.kr'),
('2400:0000::', '12', 'whois.apnic.net'),
('2600:0000::', '12', 'whois.arin.net'),
('2610:0000::', '23', 'whois.arin.net'),
('2620:0000::', '23', 'whois.arin.net'),
('2630:0000::', '12', 'whois.arin.net'),
('2800:0000::', '12', 'whois.lacnic.net'),
('2A00:0000::', '12', 'whois.ripe.net'),
('2A10:0000::', '12', 'whois.ripe.net'),
('2C00:0000::', '12', 'whois.afrinic.net'),
]

# print('local lantian_whois = require "lantian_whois";')
# print('local ip = ngx.var.ip;')
# for ip, mask, server in as_list:
#     print('if lantian_whois.ipv6_samenet(ip, "%s", %s) then return "%s" end' % (ip, mask, server))
# print('return "whois.arin.net"')

for ip, mask, server in as_list:
    print('whois_add_mapping("%s/%s", "%s");' % (ip, mask, server))
