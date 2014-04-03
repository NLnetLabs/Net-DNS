package Net::DNS::RR::TKEY;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::TKEY - DNS TKEY resource record

=cut


use integer;

use Carp;

use Net::DNS::Parameters;
use Net::DNS::DomainName;

use constant ANY  => classbyname qw(ANY);
use constant TKEY => typebyname qw(TKEY);


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $limit = $offset + $self->{rdlength};

	( $self->{algorithm}, $offset ) = decode Net::DNS::DomainName(@_);

	@{$self}{qw(inception expiration mode error)} = unpack "\@$offset N2n2", $$data;
	$offset += 12;

	my $key_size = unpack "\@$offset n", $$data;
	$self->{key} = substr $$data, $offset + 2, $key_size;
	$offset += $key_size + 2;

	my $other_size = unpack "\@$offset n", $$data;
	$self->{other} = substr $$data, $offset + 2, $other_size;
	$offset += $other_size + 2;

	croak('corrupt TKEY data') unless $offset == $limit;	# more or less FUBAR
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless defined $self->{algorithm};
	my $rdata = $self->{algorithm}->encode;

	$rdata .= pack 'N2n2', $self->inception, $self->expiration, $self->mode, $self->error;

	my $key = $self->key;					# RFC2930(2.7)
	$rdata .= pack 'na*', length $key, $key;

	my $other = $self->other;				# RFC2930(2.8)
	$rdata .= pack 'na*', length $other, $other;
	return $rdata;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	croak 'zone file representation not defined for TKEY' if shift;
}


sub class {				## overide RR method
	return 'ANY';
}

sub encode {				## overide RR method
	my $self = shift;

	my $owner = $self->{owner}->encode();
	my $rdata = eval { $self->encode_rdata() } || '';
	return pack 'a* n2 N n a*', $owner, TKEY, ANY, 0, length $rdata, $rdata;
}


sub algorithm {
	my $self = shift;

	$self->{algorithm} = new Net::DNS::DomainName(shift) if scalar @_;
	$self->{algorithm}->name if defined wantarray;
}


sub inception {
	my $self = shift;

	$self->{inception} = 0 + shift if scalar @_;
	return $self->{inception} || 0;
}


sub expiration {
	my $self = shift;

	$self->{expiration} = 0 + shift if scalar @_;
	return $self->{expiration} || 0;
}


sub mode {
	my $self = shift;

	$self->{mode} = 0 + shift if scalar @_;
	return $self->{mode} || 0;
}


sub error {
	my $self = shift;

	$self->{error} = 0 + shift if scalar @_;
	return $self->{error} || 0;
}


sub key {
	my $self = shift;

	$self->{key} = shift if scalar @_;
	$self->{key} || "";
}


sub other {
	my $self = shift;

	$self->{other} = shift if scalar @_;
	$self->{other} || "";
}


sub other_data {&other}			## historical

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;

=head1 DESCRIPTION

Class for DNS Transaction Signature (TKEY) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 algorithm

    $algorithm = $rr->algorithm;
    $rr->algorithm( $algorithm );

The algorithm name is in the form of a domain name with the same
meaning as in [RFC 2845].  The algorithm determines how the secret
keying material agreed to using the TKEY RR is actually used to derive
the algorithm specific key.

=head2 inception

    $inception = $rr->inception;
    $rr->inception( $inception );

Time expressed as the number of non-leap seconds modulo 2**32 since the
beginning of January 1970 GMT.

=head2 expiration

    $expiration = $rr->expiration;
    $rr->expiration( $expiration );

Time expressed as the number of non-leap seconds modulo 2**32 since the
beginning of January 1970 GMT.

=head2 mode

    $mode = $rr->mode;
    $rr->mode( $mode );

The mode field specifies the general scheme for key agreement or the
purpose of the TKEY DNS message, as defined in [RFC2930(2.5)].

=head2 error

    $error = $rr->error;
    $rr->error( $error );

The error code field is an extended RCODE.

=head2 key

    $key = $rr->key;
    $rr->key( $key );

Sequence of octets representing the key exchange data.
The meaning of this data depends on the mode.

=head2 other

    $other = $rr->other;
    $rr->other( $other );

Not defined in [RFC2930] specification but may be used in future
extensions.


=head1 COPYRIGHT

Copyright (c)2000 Andrew Tridgell. 

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC2930

=cut
