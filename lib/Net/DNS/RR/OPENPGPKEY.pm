package Net::DNS::RR::OPENPGPKEY;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::OPENPGPKEY - DNS OPENPGPKEY resource record

=cut


use integer;

use MIME::Base64;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $length = $self->{rdlength};
	$self->keysbin( substr $$data, $offset, $length );
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	pack 'a*', $self->keysbin || '';
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	my @base64 = split /\s+/, encode_base64( $self->keysbin );
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->keys(@_);
}


sub keys {
	my $self = shift;

	$self->keysbin( MIME::Base64::decode( join "", @_ ) ) if scalar @_;
	return MIME::Base64::encode( $self->keysbin(), "" ) if defined wantarray;
}


sub keysbin {
	my $self = shift;

	$self->{keysbin} = shift if scalar @_;
	$self->{keysbin} || "";
}

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name OPENPGPKEY keys');

=head1 DESCRIPTION

Class for OpenPGP Key (OPENPGPKEY) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 keys

    $keys = $rr->keys;
    $rr->keys( $keys );

Base64 encoded representation of the binary OpenPGP public key material.

=head2 keysbin

    $keysbin = $rr->keysbin;
    $rr->keysbin( $keysbin );

Binary representation of the public key material.
The key material is a simple concatenation of OpenPGP keys in RFC4880 format.


=head1 COPYRIGHT

Copyright (c)2014 Dick Franks

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, draft-ietf-dane-openpgpkey

=cut
