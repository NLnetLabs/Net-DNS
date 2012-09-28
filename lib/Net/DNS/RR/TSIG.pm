package Net::DNS::RR::TSIG;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];

use base Net::DNS::RR;

=head1 NAME

Net::DNS::RR::TSIG - DNS TSIG resource record

=cut


use strict;
use integer;

use Net::DNS::Parameters;
use Net::DNS::DomainName;

use constant ANY  => classbyname qw(ANY);
use constant TSIG => typebyname qw(TSIG);

use Digest::HMAC_MD5;
use MIME::Base64;

use constant DEFAULT_ALGORITHM => 'HMAC-MD5.SIG-ALG.REG.INT';
use constant DEFAULT_FUDGE     => 300;


sub new {				## decode rdata from wire-format octet string
	my $class = shift;
	my $self = bless shift, $class;
	my ( $data, $offset ) = @_;

	( $self->{algorithm}, $offset ) = decode Net::DNS::DomainName(@_);

	# Design decision: Use 32 bits, which will work until the end of time()!
	@{$self}{qw(time_signed fudge)} = unpack "\@$offset xxN n", $$data;
	$offset += 8;

	my $mac_size = unpack "\@$offset n", $$data;
	$self->{macbin} = unpack "\@$offset xx a$mac_size", $$data;
	$offset += $mac_size + 2;

	@{$self}{qw(original_id error)} = unpack "\@$offset nn", $$data;
	$offset += 4;

	my $other_size = unpack "\@$offset n", $$data;
	$self->{other} = unpack "\@$offset xx a$other_size", $$data;

	return $self;
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	my ( $offset, $hash, $packet ) = @_;

	my $macbin = $self->macbin;
	unless ($macbin) {
		my $key	     = $self->key || return '';
		my $sig_time = $self->time_signed;
		my $function = $self->sign_func;
		my $sigdata  = $self->sig_data($packet);	# form data to be signed
		$macbin = $self->macbin( &$function( $key, $sigdata ) );
		$self->original_id( $packet->header->id );
	}

	my $rdata = $self->{algorithm}->encode(0);

	# Design decision: Use 32 bits, which will work until the end of time()!
	$rdata .= pack 'xxN n', $self->time_signed, $self->fudge;

	$rdata .= pack 'na*', length($macbin), $macbin;

	$rdata .= pack 'nn', $self->original_id, $self->{error} || 0;

	my $other = $self->other || '';
	$rdata .= pack 'na*', length($other), $other;
	return $rdata;
}


sub rdatastr {				## format rdata portion of RR string.
	my $self = shift;

	join ' ', $self->algorithm, $self->error, $self->other || '';
}


sub new_from_string {			## populate RR from rdata string
	my $class = shift;
	my $self = bless shift, $class;

	$self->key(@_) if @_;

	return $self;
}


sub encode {				## overide RR method
	my $self = shift;

	my $kname = new Net::DNS::DomainName($self->name )->encode(0);  # uncompressed key name
	my $rdata = eval { $self->encode_rdata(@_) } || '';
	return pack 'a* n2 N n a*', $kname, TSIG, ANY, 0, length $rdata, $rdata;
}

sub algorithm {
	my $self = shift;

	$self->{algorithm} = new Net::DNS::DomainName(shift) if @_;
	$self->{algorithm} ||= new Net::DNS::DomainName(DEFAULT_ALGORITHM);
	$self->{algorithm}->name if defined wantarray;
}

sub key {
	my $self = shift;

	$self->{key} = shift if @_;
	$self->{key} || "";
}

sub time_signed {
	my $self = shift;

	$self->{time_signed} = shift if @_;
	return 0 + ( $self->{time_signed} || time() );
}

sub fudge {
	my $self = shift;

	$self->{fudge} = shift if @_;
	return 0 + ( $self->{fudge} || DEFAULT_FUDGE );
}

sub mac {
	unpack "H*", shift->macbin;
}

sub macbin {
	my $self = shift;

	$self->{macbin} = shift if @_;
	$self->{macbin} || "";
}

sub original_id {
	my $self = shift;

	$self->{original_id} = shift if @_;
	return 0 + ( $self->{original_id} || 0 );
}

sub error {
	my $self = shift;
	$self->{error} = rcodebyname(shift) if @_;
	rcodebyval( $self->{error} || 0 );
}

sub other {
	my $self = shift;

	$self->{other} = shift if @_;
	return 0 + ( $self->{other} || 0 );
}

sub other_data {&other}

sub sign_func {
	my $self = shift;

	$self->{sign_func} = shift if @_;
	$self->{sign_func} || \&_sign_hmac;
}

sub sig_data {
	my ( $self, $packet ) = @_;

	my @additional = grep { $_->type ne 'TSIG' } @{$packet->{additional}};
	$packet->{additional} = [@additional];

	# Add the request MAC if present (used to validate responses).
	my $sigdata = '';
	$sigdata = pack 'H*', $self->{request_mac} if $self->{request_mac};

	$sigdata .= $packet->data;
	push @{$packet}{additional}, $self;

	my $kname = new Net::DNS::DomainName($self->name )->encode(0);	# uncompressed key name
	$sigdata .= pack 'a* n N', $kname, ANY, 0;

	$sigdata .= $self->{algorithm}->encode();		# uncompressed algorithm name

	# Design decision: Use 32 bits, which will work until the end of time()!
	$sigdata .= pack 'xxN n', $self->{time_signed}, $self->fudge;

	$sigdata .= pack 'n', $self->{error} || 0;

	my $other = $self->other || '';
	$sigdata .= pack 'na*', length($other), $other;

	return $sigdata;
}


# Default signing function using the HMAC-MD5 algorithm.
# This can be overridden using the sign_func attribute.

sub _sign_hmac {
	my $hmac = new Digest::HMAC_MD5( decode_base64(shift) );
	$hmac->add(shift);
	$hmac->digest;
}

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;

=head1 DESCRIPTION

Class for DNS Transaction Signature (TSIG) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 algorithm

    $algorithm = $rr->algorithm;

A domain name which specifies the name of the algorithm.

=head2 key

    $key = $rr->key;

Base64 encoded key.

=head2 time_signed

    $time_signed = $rr->time_signed;

Signing time as the number of seconds since 1 Jan 1970 00:00:00 UTC.
The default signing time is the current time.

=head2 fudge

    $fudge = $rr->fudge;

"fudge" represents the permitted error in the signing time.
The default fudge is 300 seconds.

=head2 mac

Returns the message authentication code (MAC) as a string of hex
characters.  The programmer must call the Net::DNS::Packet data()
object method before this will return anything meaningful.

=cut


=head2 macbin

    $macbin = $rr->macbin;

Binary message authentication code (MAC).

=head2 original_id

    $original_id = $rr->original_id;

The message ID from the header of the original packet.

=head2 error

     $rcode = $tsig->error;

Returns the RCODE covering TSIG processing.  Common values are
NOERROR, BADSIG, BADKEY, and BADTIME.  See RFC 2845 for details.


=head2 other

    $other = $rr->other;

This field should be empty unless the error is BADTIME, in which
case it will contain the server time as the number of seconds since
1 Jan 1970 00:00:00 UTC.

=head2 sign_func

    $sign_func = $rr->sign_func;

This sets the signing function to be used for this TSIG record.
The default signing function is HMAC-MD5.

=head2 sig_data

     $sigdata = $tsig->sig_data($packet);

Returns the packet packed according to RFC2845 in a form for signing. This
is only needed if you want to supply an external signing function, such as is
needed for TSIG-GSS.



=head1 TSIG Keys

TSIG keys are symmetric HMAC-MD5 keys generated using the following command:

	$ dnssec-keygen -a HMAC-MD5 -b 512 -n HOST <keyname>

	The key will be stored in the file K<keyname>+157+<keyid>.private

    where
	<keyname> is the DNS name of the key.

	<keyid> is the (generated) numerical identifier used to distinguish this key.

It is recommended that the keyname be the fully qualified domain name of the relevant host.


=head1 Configuring BIND Nameserver

The following lines must be added to the /etc/named.conf file:

    key <keyname> {
	algorithm HMAC-MD5;
	secret "<keydata>";
    };

<keyname> is the name of the key chosen when the key was generated.

<keydata> is the string found on the Key: line in the generated key file.



=head1 ACKNOWLEDGMENT

Most of the code in the Net::DNS::RR::TSIG module was contributed
by Chris Turbeville. 

Support for external signing functions was added by Andrew Tridgell.


=head1 BUGS

A 32-bit representation of time is used, contrary to RFC2845 which
demands 48 bits.  This design decision will need to be reviewed
before the code stops working on 7 February 2106.

HMAC-MD5.SIG-ALG.REG.INT is the only algorithm currently supported.
You can use other algorithms by supplying an appropriate sign_func.


=head1 COPYRIGHT

Copyright (c)2002 Michael Fuhr. 

Portions Copyright (c)2002-2004 Chris Reinhardt.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC2845

=cut
