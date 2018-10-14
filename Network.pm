package Network;

use strict;
use warnings;
use Data::Dumper;

use Net::Pcap;

use Ethernet;
use IPvX;
use TCP;

sub new {
    my ($class, %args) = @_;

    $args{ethernet_cs} = new Ethernet;
    $args{ethernet_cs}->sourcemac($args{srcmac});
    $args{ethernet_cs}->destmac($args{dstmac});
    $args{ethernet_sc} = new Ethernet;
    $args{ethernet_sc}->sourcemac($args{dstmac});
    $args{ethernet_sc}->destmac($args{srcmac});

    if (defined $args{dstip4}) {
	$args{ethernet_cs}->ethtype(0x0800);
	$args{ethernet_sc}->ethtype(0x0800);
	$args{ip_cs} = new IPvX(type => 4);
	$args{ip_sc} = new IPvX(type => 4);
	$args{ip_cs}->sourceip($args{srcip4});
	$args{ip_cs}->destip($args{dstip4});
	$args{ip_sc}->sourceip($args{dstip4});
	$args{ip_sc}->destip($args{srcip4});
    } else {
	$args{ethernet_cs}->ethtype(0x86dd);
	$args{ethernet_sc}->ethtype(0x86dd);
	$args{ip_cs} = new IPvX(type => 6);
	$args{ip_sc} = new IPvX(type => 6);
	$args{ip_cs}->sourceip($args{srcip6});
	$args{ip_cs}->destip($args{dstip6});
	$args{ip_sc}->sourceip($args{dstip6});
	$args{ip_sc}->destip($args{srcip6});
    }

    $args{cs_seq} = int(rand(256 * 65536));
    $args{sc_seq} = int(rand(256 * 65536));

    $args{tv_sec} = time();
    $args{tv_usec} = 100;

    return bless \%args, $class;
}

sub tick {
    my ($self) = @_;

    $self->{tv_usec} += 50;
    if ($self->{tv_usec} >= 1000000) {
	$self->{tv_sec} += 1;
	$self->{tv_usec} = 0;
    }

    my %header = (
	len => 0,
	caplen => 0,
	tv_sec => $self->{tv_sec},
	tv_usec => $self->{tv_usec}
    );
    return %header;
}

sub handshake {
    my ($self) = @_;

    my $tcp;
    my %header;

    # SYN
    $tcp = new TCP(sourceport=>$self->{srcport}, destport=>$self->{dstport});
    $tcp->seq($self->{cs_seq});
    $tcp->ack(0);
    $tcp->flag_syn();
    $tcp->payload("");
    $self->{ip_cs}->payload($tcp);
    $self->{ethernet_cs}->payload($self->{ip_cs});

    %header = $self->tick();
    $header{caplen} = $header{len} = length($self->{ethernet_cs}->payload());
    pcap_dump($self->{dumper}, \%header, $self->{ethernet_cs}->payload());

    $self->{cs_seq}++;

    # SYN/ACK
    $tcp = new TCP(sourceport=>$self->{dstport}, destport=>$self->{srcport});
    $tcp->seq($self->{sc_seq});
    $tcp->ack($self->{cs_seq});
    $tcp->flag_syn();
    $tcp->flag_ack();
    $tcp->payload("");
    $self->{ip_sc}->payload($tcp);
    $self->{ethernet_sc}->payload($self->{ip_sc});

    %header = $self->tick();
    $header{caplen} = $header{len} = length($self->{ethernet_sc}->payload());
    pcap_dump($self->{dumper}, \%header, $self->{ethernet_sc}->payload());

    $self->{sc_seq}++;

    # ACK
    $tcp = new TCP(sourceport=>$self->{srcport}, destport=>$self->{dstport});
    $tcp->seq($self->{cs_seq});
    $tcp->ack($self->{sc_seq});
    $tcp->flag_ack();
    $tcp->payload("");
    $self->{ip_cs}->payload($tcp);
    $self->{ethernet_cs}->payload($self->{ip_cs});

    %header = $self->tick();
    $header{caplen} = $header{len} = length($self->{ethernet_cs}->payload());
    pcap_dump($self->{dumper}, \%header, $self->{ethernet_cs}->payload());
}

sub fin {
    my ($self) = @_;

    my $tcp;
    my %header;

    # FIN S->C
    $tcp = new TCP(sourceport=>$self->{dstport}, destport=>$self->{srcport});
    $tcp->seq($self->{sc_seq});
    $tcp->ack($self->{cs_seq});
    $tcp->flag_fin();
    $tcp->flag_ack();
    $tcp->payload("");
    $self->{ip_sc}->payload($tcp);
    $self->{ethernet_sc}->payload($self->{ip_sc});

    %header = $self->tick();
    $header{caplen} = $header{len} = length($self->{ethernet_sc}->payload());
    pcap_dump($self->{dumper}, \%header, $self->{ethernet_sc}->payload());

    # FIN C->S
    $tcp = new TCP(sourceport=>$self->{srcport}, destport=>$self->{dstport});
    $tcp->seq($self->{cs_seq});
    $tcp->ack($self->{sc_seq});
    $tcp->flag_fin();
    $tcp->flag_ack();
    $tcp->payload("");
    $self->{ip_cs}->payload($tcp);
    $self->{ethernet_cs}->payload($self->{ip_cs});

    %header = $self->tick();
    $header{caplen} = $header{len} = length($self->{ethernet_cs}->payload());
    pcap_dump($self->{dumper}, \%header, $self->{ethernet_cs}->payload());
}

sub client_to_server {
    my ($self, $all_payload) = @_;

    my $tcp;
    my %header;

    do {
	my $payload = "";
	if (length($all_payload) > 1460) {
	    $payload = substr($all_payload, 0, 1460);
	} else {
	    $payload = $all_payload;
	}

	# Payload C->S
	$tcp = new TCP(sourceport=>$self->{srcport}, destport=>$self->{dstport});
	$tcp->seq($self->{cs_seq});
	$tcp->ack($self->{sc_seq});
	$tcp->flag_ack();
	$tcp->payload($payload);
	$self->{ip_cs}->payload($tcp);
	$self->{ethernet_cs}->payload($self->{ip_cs});

	%header = $self->tick();
	$header{caplen} = $header{len} = length($self->{ethernet_cs}->payload());
	pcap_dump($self->{dumper}, \%header, $self->{ethernet_cs}->payload());

	$self->{cs_seq} += length($payload);

	# ACK S->C
	$tcp = new TCP(sourceport=>$self->{dstport}, destport=>$self->{srcport});
	$tcp->seq($self->{sc_seq});
	$tcp->ack($self->{cs_seq});
	$tcp->flag_ack();
	$tcp->payload("");
	$self->{ip_sc}->payload($tcp);
	$self->{ethernet_sc}->payload($self->{ip_sc});

	%header = $self->tick();
	$header{caplen} = $header{len} = length($self->{ethernet_sc}->payload());
	pcap_dump($self->{dumper}, \%header, $self->{ethernet_sc}->payload());

	if (length($all_payload) < 1460) {
	    $all_payload = "";
	} else {
	    $all_payload = substr($all_payload, 1460);
	}
    } while ($all_payload ne "");
}

sub server_to_client {
    my ($self, $all_payload) = @_;

    my $tcp;
    my %header;

    do {
	my $payload = "";
	if (length($all_payload) > 1460) {
	    $payload = substr($all_payload, 0, 1460);
	} else {
	    $payload = $all_payload;
	}

	# Payload S->C
	$tcp = new TCP(sourceport=>$self->{dstport}, destport=>$self->{srcport});
	$tcp->seq($self->{sc_seq});
	$tcp->ack($self->{cs_seq});
	$tcp->flag_ack();
	$tcp->payload($payload);
	$self->{ip_sc}->payload($tcp);
	$self->{ethernet_sc}->payload($self->{ip_sc});

	%header = $self->tick();
	$header{caplen} = $header{len} = length($self->{ethernet_sc}->payload());
	pcap_dump($self->{dumper}, \%header, $self->{ethernet_sc}->payload());

	$self->{sc_seq} += length($payload);

	# ACK C->S
	$tcp = new TCP(sourceport=>$self->{srcport}, destport=>$self->{dstport});
	$tcp->seq($self->{cs_seq});
	$tcp->ack($self->{sc_seq});
	$tcp->flag_ack();
	$tcp->payload("");
	$self->{ip_cs}->payload($tcp);
	$self->{ethernet_cs}->payload($self->{ip_cs});

	%header = $self->tick();
	$header{caplen} = $header{len} = length($self->{ethernet_cs}->payload());
	pcap_dump($self->{dumper}, \%header, $self->{ethernet_cs}->payload());

	if (length($all_payload) < 1460) {
	    $all_payload = "";
	} else {
	    $all_payload = substr($all_payload, 1460);
	}
    } while ($all_payload ne "");
}

1;
