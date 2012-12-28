package Net::DNS::RR::L32;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1]; # Previous revision 1050

use base Net::DNS::RR;

=head1 NAME

Net::DNS::RR::L32 - DNS L32 resource record

=cut


use strict;
use integer;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	@{$self}{qw(preference locator32)} = unpack "\@$offset n a4", $$data;
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless $self->{locator32} && length $self->{locator32};
	pack 'n a4', $self->{preference}, $self->{locator32};
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{locator32} && length $self->{locator32};
	return join ' ', $self->preference, $self->locator32;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->$_(shift) for qw(preference locator32);
}


sub preference {
	my $self = shift;

	$self->{preference} = shift if @_;
	return 0 + ( $self->{preference} || 0 );
}

sub locator32 {
	my $self = shift;
	my $prfx = shift;

	$self->{locator32} = pack 'C* @4', split /\./, $prfx if defined $prfx;

	join '.', unpack 'C4', $self->{locator32} if defined wantarray;
}

__PACKAGE__->set_rrsort_func(				## sort RRs in numerically ascending order.
	'preference',
	sub {
		my ( $a, $b ) = ( $Net::DNS::a, $Net::DNS::b );
		$a->{preference} <=> $b->{preference};
	} );


__PACKAGE__->set_rrsort_func(
	'default_sort',
	__PACKAGE__->get_rrsort_func('preference')

	);

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name IN L32 preference locator32');

    $rr = new Net::DNS::RR(
	name	   => 'example.com',
	type	   => 'L32',
	preference => 10,
	locator32  => '10.1.02.0'
	);

=head1 DESCRIPTION

Class for DNS 32-bit Locator (L32) resource records.

The L32 resource record is used to hold 32-bit Locator values for
ILNPv4-capable nodes.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 preference

    $preference = $rr->preference;

A 16 bit unsigned integer in network byte order that indicates the
relative preference for this L32 record among other L32 records
associated with this owner name.  Lower values are preferred over
higher values.

=head2 locator32

    $locator32 = $rr->locator32;

The Locator32 field is an unsigned 32-bit integer in network byte
order that has the same syntax and semantics as a 32-bit IPv4
routing prefix.


=head1 COPYRIGHT

Copyright (c)2012 Dick Franks.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC6742

=cut
