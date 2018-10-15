#!/usr/bin/perl -w

#
# Copyright (c) 2018, Edwin Groothuis
# All rights reserved.
#
# See LICENSE.txt for further details
#

package TCP;

use strict;
use warnings;
use bytes;

use Data::Dumper;

sub new {
    my ($class, %args) = @_;

    # Default

    $args{payload} = "NO PAYLOAD";;
    $args{ack} = 0;
    $args{fin} = 0;
    $args{rst} = 0;
    $args{syn} = 0;

    return bless \%args, $class;
}

sub sourceport {
    my ($self, $port) = @_;

    $self->{sourceport} = $port;
}

sub destport {
    my ($self, $port) = @_;

    $self->{destport} = $port;
}

sub seq {
    my ($self, $num) = @_;

    $self->{seqnr} = $num;
}

sub ack {
    my ($self, $num) = @_;

    $self->{acknr} = $num;
}

sub flag_ack {
    my ($self) = @_;

    $self->{ack} = 1;
}

sub flag_fin {
    my ($self) = @_;

    $self->{fin} = 1;
}

sub flag_syn {
    my ($self) = @_;

    $self->{syn} = 1;
}

sub flag_rst {
    my ($self) = @_;

    $self->{rst} = 1;
}

sub payload {
    my ($self, $value) = @_;

    if (defined $value) {
	$self->{payload} = $value;
	return;
    }

    my $flags = 0;
    $flags |= 1 if ($self->{fin} == 1);
    $flags |= 2 if ($self->{syn} == 1);
    $flags |= 4 if ($self->{rst} == 1);
    $flags |= 16 if ($self->{ack} == 1);

    my $si = $self->{ip}->{ip}->{sourceip};
    my @si = @{$si};
    my $di = $self->{ip}->{ip}->{destip};
    my @di = @{$di};

    my $tcp_pseudo = pack("CCCC CCCC CC n",
	$si[0], $si[1], $si[2], $si[3],
	$di[0], $di[1], $di[2], $di[3],
	0, 6, 20 + length($self->{payload}));

    my $payload = pack("nn NN CCn nn",
	$self->{sourceport}, $self->{destport},
	$self->{seqnr}, $self->{acknr},
	5 << 4 + 0, $flags, 1000,
	0, $flags) . $self->{payload};

    my $checksum = $self->checksum($tcp_pseudo . $payload);

    $payload = pack("nn NN CCn vn",
	$self->{sourceport}, $self->{destport},
	$self->{seqnr}, $self->{acknr},
	5 << 4 + 0, $flags, 1000,
	$checksum, $flags);
    return $payload . $self->{payload};
}

sub checksum {
    my ($self, $msg) = @_;

    my $len_msg = length($msg);
    my $num_short = $len_msg / 2;
    my $chk = 0;
    foreach my $short (unpack("S$num_short", $msg)) {
	$chk += $short;
    }
    $chk += unpack("C", substr($msg, $len_msg - 1, 1)) if ($len_msg % 2 != 0);
    $chk = ($chk >> 16) + ($chk & 0xffff);
    return (~(($chk >> 16) + $chk) & 0xffff);
}

1;
