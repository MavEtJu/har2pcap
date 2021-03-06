package IPvX;

#
# Copyright (c) 2018, Edwin Groothuis
# All rights reserved.
#
# See LICENSE.txt for further details
#

use strict;
use warnings;
use bytes;

use Data::Dumper;

use HAR2Pcap::IPv4;
use HAR2Pcap::IPv6;

sub new {
    my ($class, %args) = @_;

    if ($args{type} == 4) {
	$args{ip} = new IPv4;
    }
    if ($args{type} == 6) {
	$args{ip} = new IPv6;
    }

    return bless \%args, $class;
}

sub sourceip {
    my ($self, $ip) = @_;

    $self->{ip}->sourceip($ip);
}

sub destip {
    my ($self, $ip) = @_;

    $self->{ip}->destip($ip);
}

sub payload {
    my ($self, $value) = @_;

    if (defined $value) {
	$self->{ip}->payload($value);
	return;
    }
    return $self->{ip}->payload();
}

1;
