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
use bytes;

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

    my $checksum = $self->checksum($payload);

    $payload = pack("CCn nn CCn CCCC CCCC",
	($self->{version} << 4) | 5, 0, 20 + length($self->{payload}),
	$self->{identification}, 0,
	$self->{ttl}, $self->{protocol}, $checksum,
	$si[0], $si[1], $si[2], $si[3],
	$di[0], $di[1], $di[2], $di[3],
	);
    return $payload . $self->{payload};
}

sub checksum {
    my ($self, $msg) = @_;

    $msg = $msg . "\0" if (length($msg) % 2 == 1);

    my $len_msg = length($msg);
    my $num_short = $len_msg / 2;
    my $chk = 0;
    foreach my $short (unpack("n$num_short", $msg)) {
	$chk += $short;
    }
    $chk = ($chk >> 16) + ($chk & 0xffff);
    return (~(($chk >> 16) + $chk) & 0xffff);
}

1;
