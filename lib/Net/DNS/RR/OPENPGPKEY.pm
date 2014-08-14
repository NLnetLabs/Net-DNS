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
	$self->keybin( substr $$data, $offset, $length );
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	pack 'a*', $self->keybin || '';
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	my $base64 = MIME::Base64::encode $self->keybin || return '';
	chomp $base64;
	return "(\n$base64 )";
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->key(@_);
}


sub key {
	my $self = shift;

	$self->keybin( MIME::Base64::decode( join "", @_ ) ) if scalar @_;
	return MIME::Base64::encode( $self->keybin(), "" ) if defined wantarray;
}


sub publickey { &key; }


sub keybin {
	my $self = shift;

	$self->{keybin} = shift if scalar @_;
	$self->{keybin} || "";
}

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name OPENPGPKEY publickey');

=head1 DESCRIPTION

Class for OpenPGP Key (OPENPGPKEY) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 key

    $key = $rr->key;
    $rr->key( $key );

Base64 encoded representation of the OpenPGP public key.

=head2 keybin

    $keybin = $rr->keybin;
    $rr->keybin( $keybin );

Binary octet representation of the OpenPGP public key.


=head1 COPYRIGHT

Copyright (c)2014 Dick Franks

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, draft-ietf-dane-openpgpkey

=cut
