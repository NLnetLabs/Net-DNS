package Net::DNS::RR::XXXX;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1]; # Previous revision 1037

use base Net::DNS::RR;

=head1 NAME

Net::DNS::RR::XXXX - DNS XXXX resource record

=cut


use strict;
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

	## Concatenate rdata attributes. Note use of string() instead of name().
	##
	##	my $foo = $self->{foo}->string;
	##
	##	join ' ', $self->{preference}, $foo;
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

	$self->{preference} = shift if @_;
	return 0 + ( $self->{preference} || 0 );
}

sub foo {
	my $self = shift;

	$self->{foo} = new Net::DNS::DomainName(shift) if @_;
	$self->{foo}->name if defined wantarray;
}



## If you wish to offer users a sorted order then you will need to
## define functions similar to these, otherwise just remove them.

# sort RRs in numerically ascending order
#__PACKAGE__->set_rrsort_func(
#	'preference',
#	sub {
#		my ( $a, $b ) = ( $Net::DNS::a, $Net::DNS::b );
#		$a->{preference} <=> $b->{preference};
#	} );
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

Returns the server selection preference.

=head2 foo

    $foo = $rr->foo;

Returns the domain name of the foo server.


=head1 COPYRIGHT

Copyright (c)YYYY John Doe.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC????

=cut
