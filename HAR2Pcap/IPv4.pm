#!/usr/bin/perl -w

#
# Copyright (c) 2018, Edwin Groothuis
# All rights reserved.
#
# See LICENSE.txt for further details
#

package IPv4;

use strict;
use warnings;
use Data::Dumper;

sub new {
    my ($class, %args) = @_;

    # Default
    $args{version} = 4;
    $args{headerlength} = 20;
    $args{identification} = 0x1234;
    $args{ttl} = 25;
    $args{protocol} = 6;

    $args{payload} = "NO PAYLOAD";;

    return bless \%args, $class;
}

sub sourceip {
    my ($self, $ip) = @_;

    my @ip = ();
    foreach my $c (split(/\./, $ip)) {
	push(@ip, 1 * $c);
    }

    $self->{sourceip} = \@ip;
}

sub destip {
    my ($self, $ip) = @_;

    my @ip = ();
    foreach my $c (split(/\./, $ip)) {
	push(@ip, 1 * $c);
    }

    $self->{destip} = \@ip;
}

sub payload {
    my ($self, $value) = @_;

    if (defined $value) {
	$self->{payload} = $value->payload();
	return;
    }

    my $si = $self->{sourceip};
    my @si = @{$si};
    my $di = $self->{destip};
    my @di = @{$di};

    my $payload = pack("CCn nn CCn CCCC CCCC",
	($self->{version} << 4) | 5, 0, 20 + length($self->{payload}),
	$self->{identification}, 0,
	$self->{ttl}, $self->{protocol}, 0,
	$si[0], $si[1], $si[2], $si[3],
	$di[0], $di[1], $di[2], $di[3],
	);
    return $payload . $self->{payload};
}

1;
