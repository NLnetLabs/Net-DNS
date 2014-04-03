package Net::DNS::RR::EUI48;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::EUI48 - DNS EUI48 resource record

=cut


use integer;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	$self->{address} = unpack "\@$offset a6", $$data;
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless $self->{address} && length $self->{address};
	pack 'a6', $self->{address};
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{address} && length $self->{address};
	return $self->address;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->address(shift);
}


sub address {
	my ( $self, $address ) = @_;
	$self->{address} = pack 'C6', map hex($_), split /[:-]/, $address if $address;
	join '-', unpack 'H2H2H2H2H2H2', $self->{address} if defined wantarray;
}

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name IN EUI48 address');

    $rr = new Net::DNS::RR(
	name	=> 'example.com',
	type	=> 'EUI48',
	address => '00-00-5e-00-53-2a'
	);

=head1 DESCRIPTION

DNS resource records for 48-bit Extended Unique Identifier (EUI48).

The EUI48 resource record is used to represent IEEE Extended Unique
Identifiers used in various layer-2 networks, ethernet for example.

EUI48 addresses SHOULD NOT be published in the public DNS.
RFC7043 describes potentially severe privacy implications resulting
from indiscriminate publication of link-layer addresses in the DNS.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 address
The address field is a 6-octet layer-2 address in network byte order.

The presentation format is hexadecimal separated by "-".


=head1 COPYRIGHT

Copyright (c)2013 Dick Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC7043

=cut
