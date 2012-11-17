package Net::DNS::RR::L64;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];

use base Net::DNS::RR;

=head1 NAME

Net::DNS::RR::L64 - DNS L64 resource record

=cut


use strict;
use integer;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	@{$self}{qw(preference locator64)} = unpack "\@$offset n a8", $$data;
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless $self->{locator64} && length $self->{locator64};
	pack 'n a8', $self->{preference}, $self->{locator64};
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{locator64} && length $self->{locator64};
	return join ' ', $self->preference, $self->locator64;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->$_(shift) for qw(preference locator64);
}


sub preference {
	my $self = shift;

	$self->{preference} = shift if @_;
	return 0 + ( $self->{preference} || 0 );
}

sub locator64 {
	my $self = shift;
	my $prfx = shift;

	$self->{locator64} = pack 'n4', map hex($_), split /:/, $prfx if defined $prfx;

	sprintf '%x:%x:%x:%x', unpack 'n4', $self->{locator64} if defined wantarray;
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
    $rr = new Net::DNS::RR('name IN L64 preference locator64');

    $rr = new Net::DNS::RR(
	name	   => 'example.com',
	type	   => 'L64',
	preference => 10,
	locator64  => '2001:0DB8:1140:1000'
	);

=head1 DESCRIPTION

Class for DNS 64-bit Locator (L64) resource records.

The L64 resource record is used to hold 64-bit Locator values for
ILNPv6-capable nodes.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 preference

    $preference = $rr->preference;

A 16 bit unsigned integer in network byte order that indicates the
relative preference for this L64 record among other L64 records
associated with this owner name.  Lower values are preferred over
higher values.

=head2 locator64

    $locator64 = $rr->locator64;

The Locator64 field is an unsigned 64-bit integer in network byte
order that has the same syntax and semantics as a 64-bit IPv6
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
