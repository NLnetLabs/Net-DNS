package Net::DNS::RR::APL;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::APL - DNS APL resource record

=cut


use integer;

use Carp;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $limit = $offset + $self->{rdlength};

	$self->{aplist} = [];
	while ( $offset < $limit ) {
		my $xlen = unpack "\@$offset x3 C", $$data;
		my $size = ( $xlen & 0x7F );
		my $item = bless {}, 'Net::DNS::RR::APL::Item';
		$item->negate(1) if $xlen & 0x80;
		@{$item}{qw(family prefix address)} = unpack "\@$offset n C x a$size", $$data;
		$offset += $size + 4;
		push @{$self->{aplist}}, $item;
	}
	croak('corrupt APL data') unless $offset == $limit;	# more or less FUBAR
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	my $rdata = '';
	return $rdata unless $self->{aplist};
	foreach ( @{$self->{aplist}} ) {
		my $address = $_->{address};
		my $xlength = $_->negate | length($address);
		$rdata .= pack 'n C2 a*', @{$_}{qw(family prefix)}, $xlength, $address;
	}
	return $rdata;
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{aplist};
	my @rdata = map $_->string, @{$self->{aplist}};
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->aplist(@_);
}


sub aplist {
	my $self = shift;

	while ( scalar @_ ) {					# parse apitem strings
		last unless $_[0] =~ m#^(!?)(\d+):(.+)/(\d+)$#;
		my $n = $1 ? 1 : 0;
		my $f = $2;
		my ( $x, $a, $p ) = split m#^[^:]+:|/#, shift;
		$self->aplist( negate => $n, family => $f, address => $a, prefix => $p );
	}

	my $aplist = $self->{aplist} ||= [];
	if ( my %argval = @_ ) {				# parse attribute=value list
		my $item = bless {}, 'Net::DNS::RR::APL::Item';
		while ( my ( $attribute, $value ) = each %argval ) {
			$item->$attribute($value) unless $attribute eq 'address';
		}
		$item->address( $argval{address} );		# address must be last
		push @$aplist, $item;
	}

	my @ap = @$aplist;
	return wantarray ? @ap : join ' ', map $_->string, @ap if defined wantarray;
}


########################################


package Net::DNS::RR::APL::Item;


sub negate {
	my $bit = 0x80;
	for ( shift->{negate} ||= 0 ) {
		return $_ & $bit unless scalar @_;
		my $set = $_ | $bit;
		$_ = (shift) ? $set : ( $set ^ $bit );
		return $_ & $bit;
	}
}


sub family {
	my $self = shift;

	$self->{family} = 0 + shift if scalar @_;
	return $self->{family} || 0;
}


sub prefix {
	my $self = shift;

	$self->{prefix} = 0 + shift if scalar @_;
	return $self->{prefix} || 0;
}


{
	use Net::DNS::RR::A;
	use Net::DNS::RR::AAAA;

	sub _address_1 {
		my $self = shift;

		return bless( {%$self}, 'Net::DNS::RR::A' )->address unless scalar @_;

		my $alength = ( $self->prefix + 7 ) >> 3;	# mask non-prefix bits, suppress nulls
		my @address = unpack "C$alength", Net::DNS::RR::A->address(shift);
		my $bitmask = 0xFF << ( 8 - $self->prefix & 7 );
		push @address, ( $bitmask & pop(@address) ) if $alength;
		for ( reverse @address ) { last if $_; pop @address }
		$self->{address} = pack 'C*', @address;
	}


	sub _address_2 {
		my $self = shift;

		return bless( {%$self}, 'Net::DNS::RR::AAAA' )->address_long unless scalar @_;

		my $alength = ( $self->prefix + 7 ) >> 3;	# mask non-prefix bits, suppress nulls
		my @address = unpack "C$alength", Net::DNS::RR::AAAA->address(shift);
		my $bitmask = 0xFF << ( 8 - $self->prefix & 7 );
		push @address, ( $bitmask & pop(@address) ) if $alength;
		for ( reverse @address ) { last if $_; pop @address }
		$self->{address} = pack 'C*', @address;
	}
}


sub address {
	for ( $_[0]->family ) {
		return &_address_1 if /1/;
		return &_address_2 if /2/;
		die 'unknown address family';
	}
}


sub string {
	my $self = shift;

	my $not = $self->negate ? '!' : '';
	my ( $family, $address, $prefix ) = ( $self->family, $self->address, $self->prefix );
	return "$not$family:$address/$prefix";
}

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name IN APL aplist');

=head1 DESCRIPTION

DNS Address Prefix List (APL) record

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 aplist

    @aplist = $rr->aplist;
  
    @aplist = $rr->aplist( '1:192.168.32.0/21', '!1:192.168.38.0/28' );
  
    @aplist = $rr->aplist( '1:224.0.0.0/4', '2:FF00:0:0:0:0:0:0:0/8' );
  
    @aplist = $rr->aplist( negate  => 1,
			   family  => 1,
			   address => '192.168.38.0',
			   prefix  => 28,
			   );

Ordered, possibly empty, list of address prefix items.
Additional items, if present, are appended to the existing list
with neither prefix aggregation nor reordering.


=head2 Net::DNS::RR::APL::Item

Each element of the prefix list is a Net::DNS::RR::APL::Item
object which is inextricably bound to the APL record which
created it.

=head2 negate

    $rr->negate(1);

    if ( $rr->negate ) {
	...
    }

Boolean attribute indicating the prefix to be an address range exclusion.

=head2 family

    $family = $rr->family;
    $rr->family( $family );

Address family discriminant.

=head2 prefix

    $prefix = $rr->prefix;
    $rr->prefix( $prefix );

Number of bits comprising the address prefix.


=head2 address

    $address = $object->address;

Address portion of the prefix list item.

=head2 string

    $string = $object->string;

Returns the prefix list item in the form required in zone files.


=head1 COPYRIGHT

Copyright (c)2008 Olaf Kolkman, NLnet Labs.

Portions Copyright (c)2011 Dick Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC3123

=cut
