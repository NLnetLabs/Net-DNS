package Net::DNS::RR::PX;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::PX - DNS PX resource record

=cut


use integer;

use Net::DNS::DomainName;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset, @opaque ) = @_;

	$self->{preference} = unpack( "\@$offset n", $$data );
	( $self->{map822},  $offset ) = decode Net::DNS::DomainName2535( $data, $offset + 2, @opaque );
	( $self->{mapx400}, $offset ) = decode Net::DNS::DomainName2535( $data, $offset + 0, @opaque );
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;
	my ( $offset, @opaque ) = @_;

	return '' unless $self->{mapx400};
	my $rdata = pack( 'n', $self->{preference} );
	$rdata .= $self->{map822}->encode( $offset + length($rdata), @opaque );
	$rdata .= $self->{mapx400}->encode( $offset + length($rdata), @opaque );
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{mapx400};
	join ' ', $self->preference, $self->{map822}->string, $self->{mapx400}->string;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->preference(shift);
	$self->map822(shift);
	$self->mapx400(shift);
}


sub preference {
	my $self = shift;

	$self->{preference} = 0 + shift if scalar @_;
	return $self->{preference} || 0;
}


sub map822 {
	my $self = shift;

	$self->{map822} = new Net::DNS::DomainName2535(shift) if scalar @_;
	$self->{map822}->name if defined wantarray;
}


sub mapx400 {
	my $self = shift;

	$self->{mapx400} = new Net::DNS::DomainName2535(shift) if scalar @_;
	$self->{mapx400}->name if defined wantarray;
}


__PACKAGE__->set_rrsort_func(		## sort RRs in numerically ascending order.
	'preference',
	sub { $Net::DNS::a->{'preference'} <=> $Net::DNS::b->{'preference'} }

	);

__PACKAGE__->set_rrsort_func( 'default_sort', __PACKAGE__->get_rrsort_func('preference') );

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name PX preference map822 mapx400');

=head1 DESCRIPTION

Class for DNS X.400 Mail Mapping Information (PX) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 preference

    $preference = $rr->preference;
    $rr->preference( $preference );

A 16 bit integer which specifies the preference
given to this RR among others at the same owner.
Lower values are preferred.

=head2 map822

    $map822 = $rr->map822;
    $rr->map822( $map822 );

A domain name element containing <rfc822-domain>, the
RFC822 part of the MIXER Conformant Global Address Mapping.

=head2 mapx400

    $mapx400 = $rr->mapx400;
    $rr->mapx400( $mapx400 );

A <domain-name> element containing the value of
<x400-in-domain-syntax> derived from the X.400 part of
the MIXER Conformant Global Address Mapping.


=head1 COPYRIGHT

Copyright (c)1997-2002 Michael Fuhr. 

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC2163

=cut
