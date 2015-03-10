package Net::DNS::RR::ISDN;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::ISDN - DNS ISDN resource record

=cut


use integer;

use Net::DNS::Text;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	( $self->{address}, $offset ) = decode Net::DNS::Text( $data, $offset );
	( $self->{sa},	    $offset ) = decode Net::DNS::Text( $data, $offset );
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless defined $self->{address};
	join '', $self->{address}->encode, $self->{sa}->encode;
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	my $address = $self->{address} || return '';
	join ' ', $address->string, $self->{sa}->string;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->address(shift);
	$self->sa( shift || '' );
}


sub defaults() {			## specify RR attribute default values
	my $self = shift;

	$self->sa('');
}


sub address {
	my $self = shift;

	$self->{address} = new Net::DNS::Text(shift) if scalar @_;
	$self->{address}->value if defined wantarray && $self->{address};
}


sub sa {
	my $self = shift;

	$self->{sa} = new Net::DNS::Text(shift) if scalar @_;
	$self->{sa}->value if defined wantarray && $self->{sa};
}

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name ISDN address sa');

=head1 DESCRIPTION

Class for DNS ISDN resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 address

    $address = $rr->address;
    $rr->address( $address );

The ISDN-address is a string of characters, normally decimal
digits, beginning with the E.163 country code and ending with
the DDI if any.

=head2 sa

    $sa = $rr->sa;
    $rr->sa( $sa );

The optional subaddress (SA) is a string of hexadecimal digits.


=head1 COPYRIGHT

Copyright (c)1997 Michael Fuhr. 

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC1183 Section 3.2

=cut
