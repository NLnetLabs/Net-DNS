package Net::DNS::RR::X25;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];

use base Net::DNS::RR;

=head1 NAME

Net::DNS::RR::X25 - DNS X25 resource record

=cut


use strict;
use integer;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $asize = unpack "\@$offset C", $$data;
	$self->{address} = unpack "\@$offset x a$asize", $$data;
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	my $length = length( $self->{address} || return '' );
	pack 'C a*', $length, $self->{address};
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	$self->address;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->address(shift);
}


sub address {
	my $self = shift;

	$self->{address} = shift if @_;
	$self->{address} || "";
}

sub psdn { &address; }

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name X25 address');

=head1 DESCRIPTION

Class for DNS X25 resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 address

    $address = $rr->address;

The PSDN-address is a string of decimal digits, beginning with
the 4 digit DNIC (Data Network Identification Code), as specified
in X.121.


=head1 COPYRIGHT

Copyright (c)1997 Michael Fuhr. 

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC1183 Section 3.1

=cut
