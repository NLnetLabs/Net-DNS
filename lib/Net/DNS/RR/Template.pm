
##
## This is the template for specifying new RR classes.
##
## Before completing the template, please read any relevant RFCs and
## add appropriate references to the document list.
##
## When completing the code sections, you may assume that required
## data is defined and that unforeseen exceptions will be caught and
## handled by the calling environment. Explicit testing for runtime
## errors detectable by perl is inefficient and should be avoided.
##
## Note that RFC3597 specifically forbids domain name compression for
## new RR subtypes. This template makes no provision for coding RR
## subtypes with compressible RDATA or downcased canonical names.
##
## After completing the template, check that the RR code is specified
## in %Net::DNS::Parameters::typesbyname and module added to MANIFEST.
##


package Net::DNS::RR::XXXX;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::XXXX - DNS XXXX resource record

=cut


use integer;

#use Net::DNS::DomainName;
#use Net::DNS::Mailbox;
#use Net::DNS::Text;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	##		$data		reference to a wire-format packet buffer
	##		$offset		location of rdata within packet buffer
	##
	## Scalar attribute
	##	$self->{preference} = unpack( "\@$offset n", $$data );
	##
	## Domain name attribute
	##	( $self->{foo}, $next ) = decode Net::DNS::DomainName( $data, $offset + 2 );
	##
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	## Scalar attribute
	##	my $rdata = pack( 'n', $self->{preference} );
	##
	## Domain name attribute
	##	$rdata .= $self->{foo}->encode;
	##
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	## Simple RRs may return rdata attributes as a single string.
	## Note use of string() instead of name().
	##
	##	my $foo = $self->{foo}->string();
	##
	##	join ' ', $self->{preference}, $foo;
	##
	## Alternatively, rdata attributes may be returned as a list.
	##
	##	my @list = ( $self->{preference}, $foo );
	##
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	##	my @rdata = @_;			# non-empty list parsed from RR string
	##
	## Scalar attribute
	##	$self->{preference} = shift;
	##
	## Domain name attribute
	##	$self->{foo} = new Net::DNS::DomainName(shift);
	##
}


sub defaults() {			## specify RR attribute default values
	my $self = shift;

	## Note that this code is executed once only after module is loaded.
	##
	##	$self->preference(0);
	##
}


sub preference {
	my $self = shift;

	$self->{preference} = 0 + shift if scalar @_;
	return $self->{preference} || 0;
}


sub foo {
	my $self = shift;

	$self->{foo} = new Net::DNS::DomainName(shift) if scalar @_;
	$self->{foo}->name if defined wantarray && $self->{foo};
}


## If you wish to offer users a sorted order then you will need to
## define functions similar to these, otherwise just remove them.

#
#__PACKAGE__->set_rrsort_func(		## sort RRs in numerically ascending order.
#	'preference',
#	sub { $Net::DNS::a->{'preference'} <=> $Net::DNS::b->{'preference'} }
#	);
#
#
#__PACKAGE__->set_rrsort_func(
#	'default_sort',
#	__PACKAGE__->get_rrsort_func('preference')
#	);
#

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name XXXX  ...     ');

=head1 DESCRIPTION

Class for DNS hypothetical (XXXX) resource record.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 preference

    $preference = $rr->preference;
    $rr->preference( $preference );

Returns the server selection preference.

=head2 foo

    $foo = $rr->foo;
    $rr->foo( $foo );

Returns the domain name of the foo server.


=head1 COPYRIGHT

Copyright (c)YYYY John Doe.

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

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC????

=cut
