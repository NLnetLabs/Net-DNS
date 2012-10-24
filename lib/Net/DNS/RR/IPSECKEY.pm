package Net::DNS::RR::IPSECKEY;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];

use base Net::DNS::RR;

=head1 NAME

Net::DNS::RR::IPSECKEY - DNS IPSECKEY resource record

=cut


use strict;
use integer;

use Carp;
use Net::DNS::DomainName;
use MIME::Base64;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $limit = $offset + $self->{rdlength};

	@{$self}{qw(precedence gatetype algorithm)} = unpack "\@$offset C3", $$data;
	$offset += 3;

	my $gatetype = $self->{gatetype};
	unless ($gatetype) {
		$self->{gateway} = undef;			# no gateway

	} elsif ( $gatetype == 1 ) {
		$self->{gateway} = unpack "\@$offset a4", $$data;
		$offset += 4;

	} elsif ( $gatetype == 2 ) {
		$self->{gateway} = unpack "\@$offset a16", $$data;
		$offset += 16;

	} elsif ( $gatetype == 3 ) {
		my $name;
		( $name, $offset ) = decode Net::DNS::DomainName($data,$offset );
		$self->{gateway} = $name;

	} else {
		croak "unknown gateway type ($gatetype)";
	}

	$self->keybin( substr $$data, $offset, $limit - $offset );
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless $self->{algorithm};
	my $gatetype   = $self->gatetype;
	my $gateway    = $self->{gateway};
	my $precedence = $self->precedence;
	my $algorithm  = $self->algorithm;
	my $keybin     = $self->keybin;
	unless ($gatetype) {
		return pack 'C3 a*', $precedence, $gatetype, $algorithm, $keybin;

	} elsif ( $gatetype == 1 ) {
		return pack 'C3 a4 a*', $precedence, $gatetype, $algorithm, $gateway, $keybin;

	} elsif ( $gatetype == 2 ) {
		return pack 'C3 a16 a*', $precedence, $gatetype, $algorithm, $gateway, $keybin;

	} elsif ( $gatetype == 3 ) {
		my $namebin = $gateway->encode;
		return pack 'C3 a* a*', $precedence, $gatetype, $algorithm, $namebin, $keybin;
	}
	die "unknown gateway type ($gatetype)";
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{algorithm};
	my @params  = map $self->$_, qw(precedence gatetype algorithm);
	my $gateway = $self->gateway;
	my $base64  = MIME::Base64::encode $self->keybin;
	chomp $base64;
	return join ' ', @params, $gateway, "(\n$base64 )" unless length($gateway) > 10;
	return join ' ', @params, "(\n$gateway\n$base64 )";
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->$_(shift) for qw(precedence gatetype algorithm gateway);
	$self->key(@_) if @_;
}


sub precedence {
	my $self = shift;

	$self->{precedence} = shift if @_;
	return 0 + ( $self->{precedence} || 0 );
}

sub gatetype {
	my $self = shift;

	$self->{gatespec} = shift if @_;
	my $gatetype = $self->{gatetype};
	return $self->{gatespec} unless defined $gatetype;
	return $gatetype;
}

sub algorithm {
	my $self = shift;

	$self->{algorithm} = shift if @_;
	return 0 + ( $self->{algorithm} || 0 );
}

sub gateway {
	my $self = shift;

	my $gatetype = $self->gatetype;
	if (@_) {
		for ( shift || '.' ) {
			( $_ eq '.' ) && do {
				$gatetype = 0;
				last;
			};
			/:.*:/ && do {
				$gatetype = 2;
				$self->{gateway} = pack 'n* @16', map hex($_), split /:/;
				last;
			};
			/\.\d+$/ && do {
				$gatetype = 1;
				$self->{gateway} = pack 'C* @4', split /\./;
				last;
			};
			/\..+/ && do {
				$gatetype = 3;
				$self->{gateway} = new Net::DNS::DomainName($_);
				last;
			};
			croak "unrecognised gateway type";
		}
		my $declared = $self->{gatespec};
		$declared = $gatetype unless defined $declared;
		delete $self->{gatespec};
		croak "gateway not type $declared" unless $gatetype == $declared;
		$self->{gatetype} = $gatetype;
	}

	if ( defined wantarray ) {
		return '.' if $gatetype == 0;
		return join '.', unpack 'C4', $self->{gateway} if $gatetype == 1;
		return sprintf '%x:%x:%x:%x:%x:%x:%x:%x', unpack 'n8', $self->{gateway} if $gatetype == 2;
		return $self->{gateway}->name if $gatetype == 3;
		croak "unknown gateway type ($gatetype)";
	}
}

sub key {
	my $self = shift;

	$self->{keybin} = MIME::Base64::decode( join "", @_ ) if @_;
	return MIME::Base64::encode( $self->keybin, "" ) if defined wantarray;
}

sub keybin {
	my $self = shift;

	$self->{keybin} = shift if @_;
	$self->{keybin} || "";
}

sub pubkey { &key; }

# sort RRs in numerically ascending order.
__PACKAGE__->set_rrsort_func(
	'precedence',
	sub {
		my ( $a, $b ) = ( $Net::DNS::a, $Net::DNS::b );
		$a->{precedence} <=> $b->{precedence};
	} );


__PACKAGE__->set_rrsort_func( 'default_sort', __PACKAGE__->get_rrsort_func('precedence') );

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name IPSECKEY precedence gatetype algorithm gateway key');

=head1 DESCRIPTION

DNS IPSEC Key Storage (IPSECKEY) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 precedence

    $precedence = $rr->precedence;

This is an 8-bit precedence for this record.  Gateways listed in
IPSECKEY records with lower precedence are to be attempted first.

=head2 gatetype

    $gatetype = $rr->gatetype;

The gateway type field indicates the format of the information that is
stored in the gateway field.

=head2 algorithm

    $algorithm = $rr->algorithm;

The algorithm type field identifies the public keys cryptographic
algorithm and determines the format of the public key field.

=head2 gateway

    $gateway = $rr->gateway;

The gateway field indicates a gateway to which an IPsec tunnel may be
created in order to reach the entity named by this resource record.

=head2 key

    $key = $rr->key;

Base64 representation of the optional public key block for the resource record.

=head2 keybin

    $keybin = $rr->keybin;

Binary representation of the public key block for the resource record.


=head1 COPYRIGHT

Copyright (c)2007 Olaf Kolkman, NLnet Labs.

Portions Copyright (c)2012 Dick Franks.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC4025

=cut
