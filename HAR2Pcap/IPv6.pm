package IPv6;

#
# Copyright (c) 2018, Edwin Groothuis
# All rights reserved.
#
# See LICENSE.txt for further details
#

use strict;
use warnings FATAL => 'all';
use Data::Dumper;

sub new {
    my ($class, %args) = @_;

    # Default
    $args{version} = 6;
    $args{hoplimit} = 25;
    $args{nextheader} = 6;	# TCP

    $args{payload} = "NO PAYLOAD";;

    return bless \%args, $class;
}

sub fixaddress {
    my ($self, $ip) = @_;

    # 2001:4b8:64::5cff:fe02:b0bd",

    my @w = split(/:/, $ip);
    my $zeros = "0:" x (8 - $#w);
    $ip =~ s/::/:$zeros/;

    # 2001:4b8:64:0:0:5cff:fe02:b0bd",
    @w = split(/:/, $ip);
    foreach my $i (0..$#w) {
	while (length($w[$i]) != 4) {
	    $w[$i] = "0" . $w[$i];
	}
    }
    $ip = join(":", @w);

    # 2001:04b8:0064:0000:0000:5cff:fe02:b0bd",
    return $ip;
}

sub sourceip {
    my ($self, $ip) = @_;

    $ip = $self->fixaddress($ip);

    my @ip = ();
    foreach my $c (split(/\:/, $ip)) {
	$c =~ /(..)(..)/;
	push(@ip, hex($1));
	push(@ip, hex($2));
    }

    $self->{sourceip} = \@ip;
}

sub destip {
    my ($self, $ip) = @_;

    $ip = $self->fixaddress($ip);

    my @ip = ();
    foreach my $c (split(/\:/, $ip)) {
	$c =~ /(..)(..)/;
	push(@ip, hex($1));
	push(@ip, hex($2));
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

    my $payload = pack("CCn nCC CCCCCCCCCCCCCCCC CCCCCCCCCCCCCCCC",
	($self->{version} << 4), 0, 0,
	length($self->{payload}), $self->{nextheader}, $self->{hoplimit},

	$si[ 0], $si[ 1], $si[ 2], $si[ 3],
	$si[ 4], $si[ 5], $si[ 6], $si[ 7],
	$si[ 8], $si[ 9], $si[10], $si[11],
	$si[12], $si[13], $si[14], $si[15],

	$di[ 0], $di[ 1], $di[ 2], $di[ 3],
	$di[ 4], $di[ 5], $di[ 6], $di[ 7],
	$di[ 8], $di[ 9], $di[10], $di[11],
	$di[12], $di[13], $di[14], $di[15],
	);
    return $payload . $self->{payload};
}

1;
