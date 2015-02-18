package Net::DNS::RR::KX;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::KX - DNS KX resource record

=cut


use integer;

use Net::DNS::DomainName;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset, @opaque ) = @_;

	$self->{preference} = unpack( "\@$offset n", $$data );
	$self->{exchange} = decode Net::DNS::DomainName2535( $data, $offset + 2, @opaque );
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;
	my ( $offset, @opaque ) = @_;

	return '' unless $self->{exchange};
	my $rdata = pack 'n', $self->preference;
	$rdata .= $self->{exchange}->encode( $offset + length($rdata), @opaque );
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{exchange};
	join ' ', $self->preference, $self->{exchange}->string;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->preference(shift);
	$self->exchange(shift);
}


sub preference {
	my $self = shift;

	$self->{preference} = 0 + shift if scalar @_;
	return $self->{preference} || 0;
}


sub exchange {
	my $self = shift;

	$self->{exchange} = new Net::DNS::DomainName2535(shift) if scalar @_;
	$self->{exchange}->name if defined wantarray && $self->{exchange};
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
    $rr = new Net::DNS::RR('name KX preference exchange');

=head1 DESCRIPTION

DNS Key Exchange Delegation (KX) record

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

=head2 exchange

    $exchange = $rr->exchange;
    $rr->exchange( $exchange );

A domain name which specifies a host willing
to act as a key exchange for the owner name.


=head1 COPYRIGHT

Copyright (c)2009 Olaf Kolkman, NLnet Labs.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC2230

=cut
