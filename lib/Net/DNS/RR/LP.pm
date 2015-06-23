package Net::DNS::RR::LP;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::LP - DNS LP resource record

=cut


use integer;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	$self->{preference} = unpack( "\@$offset n", $$data );
	$self->{locator} = decode Net::DNS::DomainName( $data, $offset + 2 );
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless $self->{locator};
	my $rdata = pack 'n', $self->preference;
	$rdata .= $self->{locator}->encode();
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{locator};
	join ' ', $self->preference, $self->{locator}->string;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->preference(shift);
	$self->locator(shift);
}


sub preference {
	my $self = shift;

	$self->{preference} = 0 + shift if scalar @_;
	$self->{preference} || 0;
}


sub locator {
	my $self = shift;

	$self->{locator} = new Net::DNS::DomainName(shift) if scalar @_;
	$self->{locator}->name if defined wantarray && $self->{locator};
}


sub fqdn { &locator; }


__PACKAGE__->set_rrsort_func(		## sort RRs in numerically ascending order.
	'preference',
	sub { $Net::DNS::a->{'preference'} <=> $Net::DNS::b->{'preference'} }

	);

__PACKAGE__->set_rrsort_func( 'default_sort', __PACKAGE__->get_rrsort_func('preference') );


1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name IN LP preference locator');

    $rr = new Net::DNS::RR(
	name	   => 'example.com',
	type	   => 'LP',
	preference => 10,
	locator	   => 'locator.example.com'
	);

=head1 DESCRIPTION

Class for DNS Locator Pointer (LP) resource records.

The LP DNS resource record (RR) is used to hold the name of a
subnetwork for ILNP.  The name is an FQDN which can then be used to
look up L32 or L64 records.  LP is, effectively, a Locator Pointer to
L32 and/or L64 records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 preference

    $preference = $rr->preference;
    $rr->preference( $preference );

A 16 bit unsigned integer in network byte order that indicates the
relative preference for this LP record among other LP records
associated with this owner name.  Lower values are preferred over
higher values.

=head2 locator

    $locator = $rr->locator;
    $rr->locator( $locator );

The Locator field contains the DNS target name that is used to
reference L32 and/or L64 records.


=head1 COPYRIGHT

Copyright (c)2012 Dick Franks.

All rights reserved.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 LICENSE

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted, provided
that the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation, and that the name of the author not be used in advertising
or publicity pertaining to distribution of the software without specific
prior written permission.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC6742

=cut
