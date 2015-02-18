package Net::DNS::RR::LOC;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::LOC - DNS LOC resource record

=cut


use integer;

use Carp;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $version = $self->{version} = unpack "\@$offset C", $$data;
	croak "LOC version $version not supported" unless $version == 0;
	@{$self}{qw(size hp vp latitude longitude altitude)} = unpack "\@$offset xC3N3", $$data;
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless defined $self->{longitude};
	pack 'C4N3', @{$self}{qw(version size hp vp latitude longitude altitude)};
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless defined $self->{longitude};
	my @angular = ( $self->latitude, ' ', $self->longitude, ' ' );
	my @linear = ( $self->altitude, $self->size, $self->hp, $self->vp );
	join ' ', @angular, join 'm ', @linear, '';
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	my @lat;
	while ( scalar @_ ) {
		my $this = shift;
		push( @lat, $this );
		last if $this =~ /[NSns]/;
	}
	$self->latitude(@lat);

	my @long;
	while ( scalar @_ ) {
		my $this = shift;
		push( @long, $this );
		last if $this =~ /[EWew]/;
	}
	$self->longitude(@long);

	foreach my $attr (qw(altitude size hp vp)) {
		$self->$attr(shift) if scalar @_;
	}

}


sub defaults() {			## specify RR attribute default values
	my $self = shift;

	$self->version(0);
	$self->parse_rdata( 0, 0, 0, 1, 10000, 10 );
}


sub latitude {
	my $self = shift;
	$self->{latitude} = _encode_lat(@_) if scalar @_;
	return _decode_lat( $self->{latitude} ) if defined wantarray;
}


sub longitude {
	my $self = shift;
	$self->{longitude} = _encode_lat(@_) if scalar @_;
	return undef unless defined wantarray;
	return _decode_lat( $self->{longitude} ) unless wantarray;
	my @long = map { s/N/E/; s/S/W/; $_ } _decode_lat( $self->{longitude} );
}


sub altitude {
	my $self = shift;
	$self->{altitude} = _encode_alt(shift) if scalar @_;
	_decode_alt( $self->{altitude} ) if defined wantarray;
}


sub size {
	my $self = shift;
	$self->{size} = _encode_prec(shift) if scalar @_;
	_decode_prec( $self->{size} ) if defined wantarray;
}


sub hp {
	my $self = shift;
	$self->{hp} = _encode_prec(shift) if scalar @_;
	_decode_prec( $self->{hp} ) if defined wantarray;
}

sub horiz_pre { &hp; }


sub vp {
	my $self = shift;
	$self->{vp} = _encode_prec(shift) if scalar @_;
	_decode_prec( $self->{vp} ) if defined wantarray;
}

sub vert_pre { &vp; }


sub latlon {
	my $self      = shift;
	my $latitude  = _decode_lat( $self->{latitude} );
	my $longitude = _decode_lat( $self->{longitude} );
	return ( $latitude, $longitude );
}


sub version {
	my $self = shift;

	$self->{version} = 0 + shift if scalar @_;
	return $self->{version} || 0;
}


########################################

no integer;

my $datum_alt = 10000000;
my $datum_loc = 0x80000000;

sub _decode_lat {
	my $msec = shift;
	return int( 0.5 + ( $msec - $datum_loc ) / 0.36 ) / 10000000 unless wantarray;
	use integer;
	my $abs = abs( $msec - $datum_loc );
	my $deg = int( $abs / 3600000 );
	my $min = int( $abs / 60000 ) % 60;
	no integer;
	my $sec = ( $abs % 60000 ) / 1000;
	return ( $deg, $min, $sec, ( $msec < $datum_loc ? 'S' : 'N' ) );
}


sub _encode_lat {
	my @ang = scalar @_ > 1 ? (@_) : ( split /[\s\260'"]+/, shift || '0' );
	my $ang = ( 0 + shift @ang ) * 3600000;
	my $neg = ( @ang ? pop @ang : '' ) =~ /[SWsw]/ && $ang > 0;
	$ang += ( @ang ? shift @ang : 0 ) * 60000;
	$ang += ( @ang ? shift @ang : 0 ) * 1000;
	return int( 0.5 + ( $neg ? $datum_loc - $ang : $datum_loc + $ang ) );
}


sub _decode_alt {
	my $cm = (shift) - $datum_alt;
	return 0.01 * $cm;
}


sub _encode_alt {
	( my $argument = shift || '0' ) =~ s/[Mm]$//;
	$argument += 0;
	return int( 0.5 + $datum_alt + 100 * $argument );
}


my @power10 = ( 0.01, 0.1, 1, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8 );

sub _decode_prec {
	my $argument = shift;
	my $mantissa = $argument >> 4;
	return $mantissa * $power10[$argument & 0x0F];
}

sub _encode_prec {
	( my $argument = shift || '0' ) =~ s/[Mm]$//;
	return 0x00 if $argument < 0.01;
	foreach my $exponent ( 0 .. 9 ) {
		next unless $argument < $power10[1 + $exponent];
		my $mantissa = int( 0.5 + $argument / $power10[$exponent] );
		return ( $mantissa & 0xF ) << 4 | $exponent;
	}
	return 0x99;
}

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name LOC latitude longitude altitude size hp vp');

=head1 DESCRIPTION

DNS geographical location (LOC) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 latitude

    $latitude = $rr->latitude;
    ($deg, $min, $sec, $ns ) = $rr->latitude;

    $rr->latitude( 42.357990 );
    $rr->latitude( 42, 21, 28.764, 'N' );
    $rr->latitude( '42 21 28.764 N' );

When invoked in scalar context, latitude is returned in degrees,
a negative ordinate being south of the equator.

When invoked in list context, latitude is returned as a list of
separate degree, minute, and second values followed by N or S
as appropriate.

Optional replacement values may be represented as single value, list
or formatted string. Trailing zero values are optional.

=head2 longitude

    $longitude = $rr->longitude;
    ($deg, $min, $sec, $ew ) = $rr->longitude;

    $rr->latitude( 71.014338 );
    $rr->latitude( 71, 0, 51.617, 'W' );
    $rr->latitude( '71 0 51.617 W' );

When invoked in scalar context, longitude is returned in degrees,
a negative ordinate being west of the prime meridian.

When invoked in list context, longitude is returned as a list of
separate degree, minute, and second values followed by E or W
as appropriate.

=head2 altitude

    $altitude = $rr->altitude;

Represents altitude, in metres, relative to the WGS 84 reference
spheroid used by GPS.

=head2 size

    $size = $rr->size;

Represents the diameter, in metres, of a sphere enclosing the
described entity.

=head2 hp

    $hp = $rr->hp;

Represents the horizontal precision of the data expressed as the
diameter, in metres, of the circle of error.

=head2 vp

    $vp = $rr->vp;

Represents the vertical precision of the data expressed as the
total spread, in metres, of the distribution of possible values.

=head2 latlon

    ($lat, $lon) = $rr->latlon;

Returns the latitude and longitude coordinate pair as
signed floating-point degrees.

=head2 version

    $version = $rr->version;
    $rr->version( $version );

Version of LOC protocol.


=head1 COPYRIGHT

Copyright (c)1997 Michael Fuhr. 

Portions Copyright (c)2011 Dick Franks. 

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC1876

=cut
