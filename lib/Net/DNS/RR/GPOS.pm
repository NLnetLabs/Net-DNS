package Net::DNS::RR::GPOS;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::GPOS - DNS GPOS resource record

=cut


use integer;

use Net::DNS::Text;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $limit = $offset + $self->{rdlength};
	( $self->{latitude},  $offset ) = decode Net::DNS::Text( $data, $offset ) if $offset < $limit;
	( $self->{longitude}, $offset ) = decode Net::DNS::Text( $data, $offset ) if $offset < $limit;
	( $self->{altitude},  $offset ) = decode Net::DNS::Text( $data, $offset ) if $offset < $limit;
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless defined $self->{altitude};
	join '', map $self->{$_}->encode, qw(latitude longitude altitude);
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless defined $self->{altitude};
	join ' ', map $self->$_, qw(latitude longitude altitude);
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->latitude(shift);
	$self->longitude(shift);
	$self->altitude(shift);
	die 'too many arguments for GPOS' if scalar @_;
}


sub defaults() {			## specify RR attribute default values
	my $self = shift;

	$self->parse_rdata(qw(0.0 0.0 0.0));
}


sub latitude {
	my $self = shift;

	$self->{latitude} = new Net::DNS::Text(shift) if scalar @_;
	$self->{latitude}->value if defined wantarray;
}

sub longitude {
	my $self = shift;

	$self->{longitude} = new Net::DNS::Text(shift) if scalar @_;
	$self->{longitude}->value if defined wantarray;
}

sub altitude {
	my $self = shift;

	$self->{altitude} = new Net::DNS::Text(shift) if scalar @_;
	$self->{altitude}->value if defined wantarray;
}

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name GPOS latitude longitude altitude');

=head1 DESCRIPTION

Class for DNS Geographical Position (GPOS) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 latitude

    $latitude = $rr->latitude;
    $rr->latitude( $latitude );

Text string representing latitude as a floating-point number.

=head2 longitude

    $longitude = $rr->longitude;
    $rr->longitude( $longitude );

Text string representing longitude as a floating-point number.

=head2 altitude

    $altitude = $rr->altitude;
    $rr->altitude( $altitude );

Text string representing altitude as a floating-point number.


=head1 COPYRIGHT

Copyright (c)1997-1998 Michael Fuhr. 

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC1712

=cut
