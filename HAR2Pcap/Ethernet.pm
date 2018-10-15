#!/usr/bin/perl -w

#
# Copyright (c) 2018, Edwin Groothuis
# All rights reserved.
#
# See LICENSE.txt for further details
#

package Ethernet;

use strict;
use warnings;
use bytes;

use Data::Dumper;

sub new {
    my ($class, %args) = @_;

    # Default
    $args{ethtype} = 0x0800;
    $args{payload} = "No payload";;

    return bless \%args, $class;
}

sub sourcemac {
    my ($self, $mac) = @_;

    my @mac = ();
    foreach my $c (split(/:/, $mac)) {
	push(@mac, hex($c));
    }

    $self->{sourcemac} = \@mac;
}

sub destmac {
    my ($self, $mac) = @_;

    my @mac = ();
    foreach my $c (split(/:/, $mac)) {
	push(@mac, hex($c));
    }

    $self->{destmac} = \@mac;
}

sub ethtype {
    my ($self, $ethtype) = @_;

    $self->{ethtype} = $ethtype;
}

sub payload {
    my ($self, $value) = @_;

    if (defined $value) {
	$self->{payload} = $value->payload();
	return;
    }

    my $sm = $self->{sourcemac};
    my @sm = @{$sm};
    my $dm = $self->{destmac};
    my @dm = @{$dm};

    my $payload = pack("CCCCCC CCCCCC n",
	$sm[0], $sm[1], $sm[2], $sm[3], $sm[4], $sm[5],
	$dm[0], $dm[1], $dm[2], $dm[3], $dm[4], $dm[5],
	$self->{ethtype});
    return $payload . $self->{payload};
}

1;
