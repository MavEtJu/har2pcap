# har2pcap
Perl implementation of HTTP Archive files (.har) to PCAP format

# Required modules

```
use Getopt::Long;
use Data::Dumper;
use JSON::PP;
use Net::Pcap;
```

# Usage

Usage: ./har2pcap.pl [options]
        --har <input file>                      default: archive.har
	--dump <output file>                    default: out.pcap
	--srcmac <source MAC address>           default: 02:00:00:11:22:33
	--dstmac <destination MAC address>      default: 02:00:00:aa:bb:cc
	--srcip4 <source IPv4 address>          default: 192.0.2.1
	--srcip6 <source IPv6 address>          default: 2001:db8:1::1
	--fakeip4 <destination IPv4 address>    default: 198.51.100.2
	--firstport <first TCP port>            default: 1024

# Output

One ```.``` will be printed for every entry in the HAR file written.

If no serverIPAddress can be found, it will default use the value
defined with the --fakeip4 option.