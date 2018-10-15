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

    my $checksum = 0;
    my $pseudo_payload = pack("nn NN CCn nn",
	$self->{sourceport}, $self->{destport},
	$self->{seqnr}, $self->{acknr},
	5 << 4 + 0, $flags, 1000,
	0, $flags) . $self->{payload};

    if ($self->{ip}->{type} == 4) {
	my $tcp_pseudo = pack("CCCC CCCC CC n",
	    $si[0], $si[1], $si[2], $si[3],
	    $di[0], $di[1], $di[2], $di[3],
	    0, 6, 20 + length($self->{payload}));
	$checksum = $self->checksum($tcp_pseudo . $pseudo_payload);
    }
    if ($self->{ip}->{type} == 6) {
	my $tcp_pseudo = pack("CCCCCCCCCCCCCCCC CCCCCCCCCCCCCCCC N SC C",
	    $si[ 0], $si[ 1], $si[ 2], $si[ 3],
	    $si[ 4], $si[ 5], $si[ 6], $si[ 7],
	    $si[ 8], $si[ 9], $si[10], $si[11],
	    $si[12], $si[13], $si[14], $si[15],
	    $di[ 0], $di[ 1], $di[ 2], $di[ 3],
	    $di[ 4], $di[ 5], $di[ 6], $di[ 7],
	    $di[ 8], $di[ 9], $di[10], $di[11],
	    $di[12], $di[13], $di[14], $di[15],
	    20 + length($self->{payload}), 0, 0, $self->{ip}->{ip}->{nextheader});

	$checksum = $self->checksum($tcp_pseudo . $pseudo_payload);
    }

    my $payload = pack("nn NN CCn vn",
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
