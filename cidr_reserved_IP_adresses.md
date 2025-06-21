<!-- markdownlint-disable MD025 -->

# IPv4 Reserved IP Addresses

|Address block (CIDR)|Range|Number of Addresses|Scope|Decsription|
|:----|:----|:----|:----|:----|
|0.0.0.0/8|0.0.0.0–0.255.255.255|16,777,216|Software|Current (local, "this") network|
|10.0.0.0/8|10.0.0.0–10.255.255.255|16,777,216|Private network|Used for local communications within a private network|
|100.64.0.0/10|100.64.0.0–100.127.255.255|4,194,304|Private network|IPv4 shared address space|Shared address space6598 for communications between a service provider and its subscriberswhen using a carrier-grade NAT|
|127.0.0.0/8|127.0.0.0–127.255.255.255|16,777,216|Host|Used for loopback addresses to the local host|
|169.254.0.0/16|169.254.0.0–169.254.255.255|65,536|Subnet|Used for link-local addresses3927 between two hosts on a single link when no IP address is otherwise specified, such as would have normally been retrieved from a DHCP server|
|172.16.0.0/12|172.16.0.0–172.31.255.255|1,048,576|Private network|Used for local communications within a private network|
|192.0.0.0/24|192.0.0.0–192.0.0.255|256|Private network|IETF Protocol Assignments, DS-Lite (/29)|
|192.0.2.0/24|192.0.2.0–192.0.2.255|256|Documentation|Assigned as TEST-NET-1, documentation and examples5737|
|192.88.99.0/24|192.88.99.0–192.88.99.255|256|Internet|Reserved.7526 Formerly used for 6to4|IPv6 to IPv4 relay3068 (included IPv6 address block IPv6 address#Special addresses|2002::/16).|
|192.168.0.0/16|192.168.0.0–192.168.255.255|65,536|Private network|Used for local communications within a private network|
|198.18.0.0/15|198.18.0.0–198.19.255.255|131,072|Private network|Used for benchmark testing of inter-network communications between two separate subnets2544|
|198.51.100.0/24|198.51.100.0–198.51.100.255|256|Documentation|Assigned as TEST-NET-2, documentation and examples|
|203.0.113.0/24|203.0.113.0–203.0.113.255|256|Documentation|Assigned as TEST-NET-3, documentation and examples|
|224.0.0.0/4|224.0.0.0–239.255.255.255|268,435,456|Internet|In use for IP multicast|multicast5771 (former Class D network)|
|233.252.0.0/24|233.252.0.0-233.252.0.255|256|Documentation|Assigned as MCAST-TEST-NET, documentation and examples (Note that this is part of the above multicast space.)|
|240.0.0.0/4|240.0.0.0–255.255.255.254|268,435,455|Internet|Reserved for future use3232 (former Class E network)|
|255.255.255.255/32|255.255.255.255|1|Subnet|Reserved for the "limited Broadcast address|broadcast" destination address6890|

# IPv4 Reserved Private Network Ranges

|Name|CIDR block|Address range|Number of addresses|Classful description
|:----|:----|:----|:----|:----|
|24-bit block|10.0.0.0/8|10.0.0.0 – 10.255.255.255|16777216|Single Class A|
|20-bit block|172.16.0.0/12|172.16.0.0 – 172.31.255.255|1048576|Contiguous range of 16 Class B blocks
|16-bit block|192.168.0.0/16|192.168.0.0 – 192.168.255.255|65536|Contiguous range of 256 Class C blocks

# IPv6 Reserved IP Addresses

|Address block (CIDR)|Range|Number of Addresses|Scope|Decsription|
|:----|:----|:----|:----|:----|
|::/128|::|::|1|Software|Unspecified address|
|::1/128|::1|::1|1|Host|Loopback address — a virtual interface that loops all traffic back to itself, the ''local host''|
|::ffff:0:0/96|::ffff:0.0.0.0|::ffff:255.255.255.255|2<sup>32</sup>|Software|IPv4-mapped addresses|
|::ffff:0:0:0/96|::ffff:0:0.0.0.0|::ffff:0:255.255.255.255|2<sup>32</sup>|Software|IPv4 translated addresses|
|64:ff9b::/96|64:ff9b::0.0.0.0|64:ff9b::255.255.255.255|2<sup>32</sup>|Global Internet|IPv4/IPv6 translation|
|64:ff9b:1::/48|64:ff9b:1::|64:ff9b:1:ffff:ffff:ffff:ffff:ffff|2<sup>80</sup>, with 2<sup>48</sup> for each IPv4|Private internets|IPv4/IPv6 translation|
|100::/64|100::|100::ffff:ffff:ffff:ffff|2<sup>64</sup>|Routing|Discard prefix|
|2001:0000::/32|2001::|2001::ffff:ffff:ffff:ffff:ffff:ffff|2<sup>96</sup>|Global Internet|Teredo tunneling|
|2001:20::/28|2001:20::|2001:2f:ffff:ffff:ffff:ffff:ffff:ffff|2<sup>100</sup>|Software|ORCHIDv2|
|2001:db8::/32|2001:db8::|2001:db8:ffff:ffff:ffff:ffff:ffff:ffff|2<sup>96</sup>|Documentation|Addresses used in documentation and example source code|
|2002::/16|2002::|2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff|2<sup>112</sup>|Global Internet|The 6to4 addressing scheme (deprecated)|
|fc00::/7|fc00::|fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff|2<sup>121</sup>|Private internets|Unique local address|
|fe80::/64 from fe80::/10|fe80::|fe80::ffff:ffff:ffff:ffff|2<sup>64</sup>|Link|Link-local address#IPv6|Link-local address|
|ff00::/8|ff00::|ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff|2<sup>120</sup>|Global Internet|Multicast address#IPv6|Multicast address|
