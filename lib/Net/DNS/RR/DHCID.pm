package Net::DNS::RR::DHCID;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];

use base Net::DNS::RR;

=head1 NAME

Net::DNS::RR::DHCID - DNS DHCID resource record

=cut


use strict;
use integer;

use MIME::Base64;

use Text::ParseWords;


sub new {				## decode rdata from wire-format octet string
	my $class = shift;
	my $self = bless shift, $class;
	my ( $data, $offset ) = @_;

	my $dlen = $self->{rdlength} - 3;
	@{$self}{qw(identifiertype digesttype digestbin)} = unpack "\@$offset nC a$dlen", $$data;

	return $self;
}


sub rr_rdata {				## encode rdata as wire-format octet string
	my $self = shift;
	my $pkt	 = shift;
	$self->encode_rdata(@_);
}

sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless defined $self->{digestbin};
	pack 'nC a*', map { $self->$_ } qw(identifiertype digesttype digestbin);
}


sub rdatastr {				## format rdata portion of RR string.
	my $self = shift;

	my $base64 = MIME::Base64::encode $self->encode_rdata, "\n\t";
	join ' ', "(\n\t", $base64, ')';
}


sub new_from_string {			## populate RR from rdata string
	my $class = shift;
	my $self  = bless shift, $class;
	my @parse = grep { not /^[()]$/ } quotewords( qw(\s+), 1, shift || "" );
	$self->parse_rdata(@parse) if @parse;
	return $self;
}

sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	my $data = MIME::Base64::decode( join '', @_ );
	my $dlen = length($data) - 3;
	@{$self}{qw(identifiertype digesttype digestbin)} = unpack "nC a$dlen", $data;
}


#   +------------------+------------------------------------------------+
#   |  Identifier Type | Identifier                                     |
#   |       Code       |                                                |
#   +------------------+------------------------------------------------+
#   |      0x0000      | The 1-octet 'htype' followed by 'hlen' octets  |
#   |                  | of 'chaddr' from a DHCPv4 client's DHCPREQUEST |
#   |                  | [7].                                           |
#   |      0x0001      | The data octets (i.e., the Type and            |
#   |                  | Client-Identifier fields) from a DHCPv4        |
#   |                  | client's Client Identifier option [10].        |
#   |      0x0002      | The client's DUID (i.e., the data octets of a  |
#   |                  | DHCPv6 client's Client Identifier option [11]  |
#   |                  | or the DUID field from a DHCPv4 client's       |
#   |                  | Client Identifier option [6]).                 |
#   |  0x0003 - 0xfffe | Undefined; available to be assigned by IANA.   |
#   |      0xffff      | Undefined; RESERVED.                           |
#   +------------------+------------------------------------------------+

sub identifiertype {
	my $self = shift;

	$self->{identifiertype} = shift if @_;
	return 0 + ( $self->{identifiertype} || 0 );
}

sub digesttype {
	my $self = shift;

	$self->{digesttype} = shift if @_;
	return 0 + ( $self->{digesttype} || 0 );
}

sub digest {
	my $self = shift;

	$self->{digestbin} = MIME::Base64::decode( join '', map { s/\s+//g; $_ } @_ ) if @_;
	MIME::Base64::encode( $self->{digestbin}, '' ) if defined wantarray;
}

sub digestbin {
	my $self = shift;

	$self->{digestbin} = shift if @_;
	$self->{digestbin} || "";
}


1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name DHCID algorithm fptype fingerprint');

=head1 DESCRIPTION

DNS RR for Encoding DHCP Information (DHCID)

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 identifiertype

    $identifiertype = $object->identifiertype;

The 16-bit identifier type describes the form of host identifier
used to construct the DHCP identity information.

=head2 digesttype

    $digesttype = $object->digesttype;

The 8-bit digest type number describes the message-digest
algorithm used to obfuscate the DHCP identity information.

=head2 digest

    $digest = $rr->digest;

Returns the digest data using base64 format.

=head2 digestbin

    $digestbin = $object->digestbin;

Returns opaque octet string representing the digest.


=head1 COPYRIGHT

Copyright (c)2009 Olaf Kolkman, NLnet Labs.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC4701

=cut
