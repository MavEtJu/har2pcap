#!/usr/bin/perl -w

package TCP;

use strict;
use warnings;
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

    my $payload = pack("nn NN CCn nn",
	$self->{sourceport}, $self->{destport},
	$self->{seqnr}, $self->{acknr},
	5 << 4 + 0, $flags, 1000,
	0, 0);
    return $payload . $self->{payload};
}

1;
