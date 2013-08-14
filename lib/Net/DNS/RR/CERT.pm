package Net::DNS::RR::CERT;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];

use base Net::DNS::RR;

=head1 NAME

Net::DNS::RR::CERT - DNS CERT resource record

=cut


use integer;

use MIME::Base64;

my %formats = (
	PKIX	=> 1,						# X.509 as per PKIX
	SPKI	=> 2,						# SPKI certificate
	PGP	=> 3,						# OpenPGP packet
	IPKIX	=> 4,						# The URL of an X.509 data object
	ISPKI	=> 5,						# The URL of an SPKI certificate
	IPGP	=> 6,						# The fingerprint and URL of an OpenPGP packet
	ACPKIX	=> 7,						# Attribute Certificate
	IACPKIX => 8,						# The URL of an Attribute Certificate
	URI	=> 253,						# URI private
	OID	=> 254,						# OID private
	);

my %r_formats = reverse %formats;


my %algorithms = (						# RFC4034 except where noted
	RSAMD5	   => 1,
	DH	   => 2,
	DSA	   => 3,
	ECC	   => 4,
	RSASHA1	   => 5,
	RESERVE123 => 123,					# RFC6014
	RESERVE251 => 251,					# RFC6014
	INDIRECT   => 252,
	PRIVATEDNS => 253,
	PRIVATEOID => 254,
	);

my %r_algorithms = reverse %algorithms;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	@{$self}{qw(format tag algorithm)} = unpack "\@$offset n2 C", $$data;
	$self->{certbin} = substr $$data, $offset + 5, $self->{rdlength} - 5;
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless $self->{certbin};
	pack "n2 C a*", @{$self}{qw(format tag algorithm certbin)};
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{certbin};
	my $format    = $r_formats{$self->{format}}	  || $self->{format};
	my $algorithm = $r_algorithms{$self->{algorithm}} || $self->{algorithm};
	my $base64    = MIME::Base64::encode $self->{certbin};
	chomp $base64;
	return "$format $self->{tag} $algorithm $base64" if length($base64) < 40;
	return "$format $self->{tag} $algorithm (\n$base64 )";
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->$_(shift) for qw(format tag algorithm);
	$self->cert(@_);
}


sub format {
	my $self = shift;

	return $self->{format} unless scalar @_;

	my $format = shift;
	$format = '<undef>' unless defined $format;
	$format = $formats{$format} || die "Unknown mnemonic: '$format'"
			if $format =~ /\D/;			# look up mnemonic
	$self->{format} = $format;
}

sub tag {
	my $self = shift;

	$self->{tag} = 0 + shift if scalar @_;
	return $self->{tag} || 0;
}

sub algorithm {
	my $self = shift;

	return $self->{algorithm} unless scalar @_;

	my $algorithm = shift;
	$algorithm = '<undef>' unless defined $algorithm;
	$algorithm = $algorithms{$algorithm} || die "Unknown mnemonic: '$algorithm'"
			if $algorithm =~ /\D/;			# look up mnemonic
	$self->{algorithm} = $algorithm;
}

sub cert {
	my $self = shift;

	$self->{certbin} = MIME::Base64::decode( join "", @_ ) if scalar @_;
	return MIME::Base64::encode( $self->certbin, "" ) if defined wantarray;
}

sub certbin {
	my $self = shift;

	$self->{certbin} = shift if scalar @_;
	$self->{certbin} || "";
}

sub certificate { &certbin; }			## historical

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name IN CERT format tag algorithm cert');

=head1 DESCRIPTION

Class for DNS Certificate (CERT) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 format

    $format =  $rr->format;

Returns the format code for the certificate (in numeric form)

=head2 tag

    $tag = $rr->tag;

Returns the key tag for the public key in the certificate

=head2 algorithm

    $algorithm = $rr->algorithm;

Returns the algorithm used by the certificate (in numeric form).

=head2 cert

    $cert = $rr->cert;

Base64 representation of the certificate.

=head2 certbin

    $certbin = $rr->certbin;

Binary representation of the certificate.


=head1 COPYRIGHT

Copyright (c)2002 VeriSign, Mike Schiraldi

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC4398

=cut
