package Net::DNS::RR::RT;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1]; # Previous revision 1037

use base Net::DNS::RR;

=head1 NAME

Net::DNS::RR::RT - DNS RT resource record

=cut


use strict;
use integer;

use Net::DNS::DomainName;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset, @opaque ) = @_;

	$self->{preference} = unpack( "\@$offset n", $$data );
	$self->{intermediate} = decode Net::DNS::DomainName2535($data,$offset+2,@opaque );
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;
	my ( $offset, @opaque ) = @_;

	return '' unless $self->{intermediate};
	pack 'n a*', $self->preference, $self->{intermediate}->encode( $offset, @opaque );
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{intermediate};
	join ' ', $self->preference, $self->{intermediate}->string;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->$_(shift) for qw(preference intermediate);
}


sub preference {
	my $self = shift;

	$self->{preference} = shift if @_;
	return 0 + ( $self->{preference} || 0 );
}

sub intermediate {
	my $self = shift;

	$self->{intermediate} = new Net::DNS::DomainName2535(shift) if @_;
	$self->{intermediate}->name if defined wantarray;
}

# sort RRs in numerically ascending order.
__PACKAGE__->set_rrsort_func(
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
    $rr = new Net::DNS::RR('name RT preference intermediate');

=head1 DESCRIPTION

Class for DNS Route Through (RT) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 preference

    $preference = $rr->preference;

 A 16 bit integer representing the preference of the route.
Smaller numbers indicate more preferred routes.

=head2 intermediate

    $intermediate = $rr->intermediate;

The domain name of a host which will serve as an intermediate
in reaching the host specified by the owner name.
The DNS RRs associated with the intermediate host are expected
to include at least one A, X25, or ISDN record.


=head1 COPYRIGHT

Copyright (c)1997-2002 Michael Fuhr. 

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC1183 Section 3.3

=cut
