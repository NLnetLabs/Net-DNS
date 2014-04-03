package Net::DNS::RR::DHCID;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::DHCID - DNS DHCID resource record

=cut


use integer;

use MIME::Base64;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $size = $self->{rdlength} - 3;
	@{$self}{qw(identifiertype digesttype digest)} = unpack "\@$offset nC a$size", $$data;
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless $self->{digest};
	pack 'nC a*', map $self->$_, qw(identifiertype digesttype digest);
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	my $base64 = MIME::Base64::encode $self->encode_rdata;
	chomp $base64;
	return length($base64) > 40 ? "(\n$base64 )" : $base64;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->rdata(@_);
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

	$self->{identifiertype} = 0 + shift if scalar @_;
	return $self->{identifiertype} || 0;
}


sub digesttype {
	my $self = shift;

	$self->{digesttype} = 0 + shift if scalar @_;
	return $self->{digesttype} || 0;
}


sub digest {
	my $self = shift;

	$self->{digest} = shift if scalar @_;
	$self->{digest} || "";
}


sub rdata {
	my $self = shift;

	if ( scalar @_ ) {
		my $data = MIME::Base64::decode( join "", @_ );
		my $size = length($data) - 3;
		@{$self}{qw(identifiertype digesttype digest)} = unpack "n C a$size", $data;
	}
	return MIME::Base64::encode( $self->encode_rdata, "" ) if defined wantarray;
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

    $identifiertype = $rr->identifiertype;
    $rr->identifiertype( $identifiertype );

The 16-bit identifier type describes the form of host identifier
used to construct the DHCP identity information.

=head2 digesttype

    $digesttype = $rr->digesttype;
    $rr->digesttype( $digesttype );

The 8-bit digest type number describes the message-digest
algorithm used to obfuscate the DHCP identity information.

=head2 digest

    $digest = $rr->digest;
    $rr->digest( $digest );

Binary representation of the digest of DHCP identity information.

=head2 rdata

The RDATA for this record is stored in master files as a single
block using Base64 representation.

White space characters may appear anywhere within the Base64 text
and will be silently ignored.



=head1 COPYRIGHT

Copyright (c)2009 Olaf Kolkman, NLnet Labs.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC4701

=cut
