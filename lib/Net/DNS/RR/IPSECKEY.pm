package Net::DNS::RR::IPSECKEY;
use base Net::DNS::RR;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


=head1 NAME

Net::DNS::RR::IPSECKEY - DNS IPSECKEY resource record

=cut


use strict;
use integer;

use Carp;
use MIME::Base64;
use Net::DNS::DomainName;

use Text::ParseWords;


sub new {				## decode rdata from wire-format octet string
	my $class = shift;
	my $self = bless shift, $class;
	my ( $data, $offset ) = @_;

	my $next = $offset + $self->{rdlength};

	@{$self}{qw(precedence gatetype algorithm)} = unpack "\@$offset C3", $$data;
	$offset += 3;

	for ( $self->{gatetype} ) {
		unless ($_) {
			$self->{gateway} = '.';			# no gateway

		} elsif ( $_ == 1 ) {
			$self->{gateway} = join '.', unpack "\@$offset C4", $$data;
			$offset += 4;

		} elsif ( $_ == 2 ) {
			$self->{gateway} = sprintf '%x:%x:%x:%x:%x:%x:%x:%x', unpack "\@$offset n8", $$data;
			$offset += 16;

		} elsif ( $_ == 3 ) {
			my $name;
			( $name, $offset ) = decode Net::DNS::DomainName($data,$offset );
			$self->{gateway} = $name->name;

		} else {
			croak "unknown gateway type ($_)";
		}
	}

	my $keybin = substr $$data, $offset, $next - $offset;
	$self->{pubkey} = encode_base64( $keybin, '' );

	return $self;
}


sub rr_rdata {				## encode rdata as wire-format octet string
	my $self = shift;
	my $pkt	 = shift;
	$self->encode_rdata(@_);
}

sub encode_rdata {				## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless defined $self->{gateway};
	my $precedence = $self->precedence;
	my $algorithm  = $self->algorithm;
	my $keybin     = decode_base64( $self->{pubkey} ) if $self->{pubkey};
	for ( $self->{gateway} || '.' ) {
		if ( $_ eq '.' ) {
			return pack 'C3 a*', $precedence, 0, $algorithm, $keybin;

		} elsif (/\.\d+/) {
			my @parse = split /\./;
			return pack 'C3 C4 @7 a*', $precedence, 1, $algorithm, @parse, $keybin;

		} elsif (/:.*:/) {
			s/^:/0:/;
			my @parse = split /:/;
			my @canon = map { /./ ? hex($_) : (0) x ( 9 - @parse ) } @parse;
			return pack 'C3 n8 @19 a*', $precedence, 2, $algorithm, @canon, $keybin;

		} elsif (/\..+/) {
			my $name = new Net::DNS::DomainName($_)->encode;
			return pack 'C3 a* a*', $precedence, 3, $algorithm, $name, $keybin;
		}
	}
}


sub rdatastr {				## format rdata portion of RR string.
	my $self = shift;

	my $precedence = $self->precedence;
	my $gatetype   = $self->gatetype;
	my $algorithm  = $self->algorithm;
	my $gateway    = $self->gateway;
	my $publickey  = $self->publickey;

	return join ' ', $precedence, $gatetype, $algorithm, '.', $publickey if $gatetype == 0;
	return join ' ', $precedence, $gatetype, $algorithm, $gateway, $publickey if $gatetype == 1;
	return join ' ', $precedence, $gatetype, $algorithm, $gateway, $publickey if $gatetype == 2;
	my $name = new Net::DNS::DomainName($gateway)->string;
	return join ' ', $precedence, $gatetype, $algorithm, $name, $publickey if $gatetype == 3;
}


sub new_from_string {				## populate RR from rdata string
	my $class = shift;
	my $self  = bless shift, $class;
	my @parse = grep {/[^()]/} quotewords( qw(\s+), 1, shift || "" );
	$self->parse_rdata(@parse) if @parse;
	return $self;
}

sub parse_rdata {				## populate RR from rdata in argument list
	my $self = shift;

	$self->precedence(shift);
	$self->gatetype(shift);
	$self->algorithm(shift);
	$self->gateway(shift);
	$self->publickey(@_);
}


sub defaults() {				## specify RR attribute default values
	my $self = shift;

	$self->precedence(10);
	$self->gateway('');
}


sub precedence {
	my $self = shift;

	$self->{precedence} = shift if @_;
	return 0 + ( $self->{precedence} || 0 );
}

sub gatetype {
	my $self = shift;
	for ( $self->{gateway} ||= '.' ) {
		return 0 if $_ eq '.';
		return 1 if /\.\d+$/;
		return 2 if /:.*:/;
		return 3 if /\..+/;
	}
}

sub algorithm {
	my $self = shift;

	$self->{algorithm} = shift if @_;
	return 0 + ( $self->{algorithm} || 0 );
}

sub gateway {
	my $self = shift;

	$self->{gateway} = shift if @_;
	$self->{gateway} || "";
}

sub pubkey {
	my $self = shift;

	$self->{pubkey} = shift if @_;
	$self->{pubkey} || "";
}

sub publickey {&pubkey}

# sort RRs in numerically ascending order.
__PACKAGE__->set_rrsort_func(
	'precedence',
	sub {
		my ( $a, $b ) = ( $Net::DNS::a, $Net::DNS::b );
		$a->{precedence} <=> $b->{precedence};
	} );


__PACKAGE__->set_rrsort_func(
	'default_sort',
	__PACKAGE__->get_rrsort_func('precedence')

	);


1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name IPSECKEY precedence gatetype algorithm gateway publickey');

=head1 DESCRIPTION

DNS IPSEC Key Storage (IPSECKEY) resource records.

=head1 METHODS

The available methods are those inherited from the base class
augmented by the type-specific methods defined in this package.

Use of undocumented features or direct access to internal data
structures is discouraged and may result in program termination
or unexpected behaviour.


=head2 precedence

    $precedence = $object->precedence;

This is an 8-bit precedence for this record.  Gateways listed in
IPSECKEY records with lower precedence are to be attempted first.

=head2 gatetype

    $gatetype = $rr->gatetype;

The gateway type field indicates the format of the information
that is stored in the gateway field.

=head2 algorithm

    $algorithm = $object->algorithm;

The algorithm type field identifies the public keys cryptographic
algorithm and determines the format of the public key field.

=head2 gateway

    $gateway = $object->gateway;

The gateway field indicates a gateway to which an IPsec tunnel
may be created in order to reach the entity named by this
resource record.

=head2 pubkey

    $pubkey = $object->pubkey;

Optional base64 encoded public key block for the resource record.


=head1 COPYRIGHT

Copyright (c)2007 Olaf Kolkman, NLnet Labs.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC4025

=cut
