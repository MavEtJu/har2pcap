#!/usr/bin/perl -w -I .

#
# Copyright (c) 2018, Edwin Groothuis
# All rights reserved.
#
# See LICENSE.txt for further details
#

use strict;
use warnings;
use bytes;

use Getopt::Long;
use Net::Pcap;
use Data::Dumper;

use JSON::PP;

use HAR2Pcap::Network;

my $dump_file = "out.pcap";
my $har_file = "archive.har";
my $src_mac = "02:00:00:11:22:33";
my $dst_mac = "02:00:00:aa:bb:cc",
my $src_ip4 = "192.0.2.1";
my $src_ip6 = "2001:db8:1::1";
my $fake_ip4 = "198.51.100.2";
my $first_port = 1024;

GetOptions(
    "dump=s"	=> \$dump_file,
    "har=s"	=> \$har_file,
    "srcmac=s"	=> \$src_mac,
    "dstmac=s"	=> \$dst_mac,
    "srcip4=s"	=> \$src_ip4,
    "srcip6=s"	=> \$src_ip6,
    "fakeip4=s"	=> \$fake_ip4,
    "firstport=s"	=> \$first_port,
    )
or usage();

sub usage {
    print <<EOF;

Usage: $0 [options]
	--har <input file>			default: $har_file
	--dump <output file>			default: $dump_file
	--srcmac <source MAC address>		default: $src_mac
	--dstmac <destination MAC address>	default: $dst_mac
	--srcip4 <source IPv4 address>		default: $src_ip4
	--srcip6 <source IPv6 address>		default: $src_ip6
	--fakeip4 <destination IPv4 address>	default: $fake_ip4
	--firstport <first TCP port>		default: $first_port

EOF
    die("Usage");
}


# Init PCAP
my $pcap = pcap_open_dead(DLT_EN10MB, 1024);
my $dumper = pcap_dump_open($pcap, $dump_file);
my $srcport = $first_port;

# For every entry...
open(FIN, $har_file) or die "Cannot open $har_file for reading";
my @lines = <FIN>;
close(FIN);
my $perl_scalar = decode_json(join("", @lines));
my %har = %{$perl_scalar};
my %log = %{$har{log}};
my @entries = @{$log{entries}};

foreach my $entrycount (0..$#entries) {
    my %entry = %{$entries[$entrycount]};

    my %request = %{$entry{request}};
    my %response = %{$entry{response}};

    # Create the request
    my $url = $request{url};
    $url =~ s%^https?://[^/]+%%;

    my $request = "$request{method} $url $request{httpVersion}\n";
    foreach my $header (@{$request{headers}}) {
	    my %header = %{$header};
	    $request .= "$header{name}: $header{value}\n";
    }
    $request .= "\n";
    if (defined $request{postData}{text}) {
	$request .= $request{postData}{text};
    } else {
    }

    # Create the response
    my $response = "$response{httpVersion} $response{status} $response{statusText}\n";
    foreach my $header (@{$response{headers}}) {
	    my %header = %{$header};
	    $response .= "$header{name}: $header{value}\n";
    }
    $response .= "\n";
    if (defined $response{content}{text}) {
	$response .= $response{content}{text};
    } else {
    }

    # Destination
    my $destip4 = undef;
    my $destip6 = undef;
    my $destip = $entry{serverIPAddress};
    if (!defined $destip) {
	print STDERR "\nNo serverIPAddress found for entry $entrycount, faking to $fake_ip4\n";
	$destip = $fake_ip4;
    }
    if ($destip =~ /:/) {
	$destip6 = $destip;
    } else {
	$destip4 = $destip;
    }

    my $network = new Network(
		    dumper => $dumper,
		    srcmac => $src_mac,
		    dstmac => $dst_mac,
		    srcip4 => $src_ip4,
		    dstip4 => $destip4,
		    srcip6 => $src_ip6,
		    dstip6 => $destip6,
		    srcport => $srcport++,
		    dstport => 80,
		    );

    $network->handshake();
    $network->client_to_server($request);
    $network->server_to_client($response);
    $network->fin();

    print STDERR ".";
}

pcap_dump_close($dumper);

print "\nOutput send to $dump_file\n";
