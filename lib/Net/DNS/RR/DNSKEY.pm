package Net::DNS::RR::DNSKEY;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::DNSKEY - DNS DNSKEY resource record

=cut


use integer;

use warnings;
use Carp;
use MIME::Base64;

#
# source: http://www.iana.org/assignments/dns-sec-alg-numbers
#
{
	my @algbyname = (		## Reserved	=> 0,	# [RFC4034][RFC4398]
		'RSAMD5'	     => 1,			# [RFC3110][RFC4034]
		'DH'		     => 2,			# [RFC2539]
		'DSA'		     => 3,			# [RFC3755][RFC2536]
					## Reserved	=> 4,	# [RFC6725]
		'RSASHA1'	     => 5,			# [RFC3110][RFC4034]
		'DSA-NSEC3-SHA1'     => 6,			# [RFC5155]
		'RSASHA1-NSEC3-SHA1' => 7,			# [RFC5155]
		'RSASHA256'	     => 8,			# [RFC5702]
					## Reserved	=> 9,	# [RFC6725]
		'RSASHA512'	     => 10,			# [RFC5702]
					## Reserved	=> 11,	# [RFC6725]
		'ECC-GOST'	     => 12,			# [RFC5933]
		'ECDSAP256SHA256'    => 13,			# [RFC6605]
		'ECDSAP384SHA384'    => 14,			# [RFC6605]

		'INDIRECT'   => 252,				# [RFC4034]
		'PRIVATEDNS' => 253,				# [RFC4034]
		'PRIVATEOID' => 254,				# [RFC4034]
					## Reserved	=> 255,	# [RFC4034]
		);

	my %algbyval = reverse @algbyname;

	my @algbynum = map { ( $_, 0 + $_ ) } ( 1 .. 250, keys %algbyval );

	my %algbyname = map { s/[^A-Za-z0-9]//g; $_ } @algbyname, @algbynum;

	sub algbyname {
		my $name = shift;
		my $key	 = uc $name;				# synthetic key
		$key =~ s/[^A-Z0-9]//g;				# strip non-alphanumerics
		return $algbyname{$key} || croak "unknown algorithm $name";
	}

	sub algbyval {
		my $value = shift;
		return $algbyval{$value} || $value;
	}
}


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $keylength = $self->{rdlength} - 4;
	@{$self}{qw(flags protocol algorithm keybin)} = unpack "\@$offset n C2 a$keylength", $$data;
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	my $keybin = $self->keybin || return '';
	pack 'n C2 a*', $self->flags, $self->protocol, $self->algorithm, $keybin;
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	my $base64 = MIME::Base64::encode $self->keybin || return '';
	my @params = map $self->$_, qw(flags protocol algorithm);
	chomp $base64;
	return join ' ', @params, "(\n$base64 ) ; Key ID =", $self->keytag;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->$_(shift) for qw(flags protocol algorithm);
	$self->key(@_);
}


sub defaults() {			## specify RR attribute default values
	my $self = shift;

	$self->algorithm(1);
	$self->protocol(3);
}


sub flags {
	my $self = shift;

	$self->{flags} = 0 + shift if scalar @_;
	return $self->{flags} || 0;
}


sub protocol {
	my $self = shift;

	$self->{protocol} = 0 + shift if scalar @_;
	return $self->{protocol} || 0;
}


sub algorithm {
	my ( $self, $arg ) = @_;

	unless ( ref($self) ) {		## class method or simple function
		my $argn = pop || croak 'undefined argument';
		return $argn =~ /[^0-9]/ ? algbyname($argn) : algbyval($argn);
	}

	return $self->{algorithm} unless defined $arg;
	return algbyval( $self->{algorithm} ) if $arg =~ /MNEMONIC/i;
	return $self->{algorithm} = algbyname($arg);
}


sub key {
	my $self = shift;

	$self->keybin( MIME::Base64::decode( join "", @_ ) ) if scalar @_;
	return MIME::Base64::encode( $self->keybin(), "" ) if defined wantarray;
}


sub publickey { &key; }


sub keybin {
	my $self = shift;

	return $self->{keybin} || '' unless scalar @_;
	delete $self->{keytag};
	$self->{keybin} = shift;
}


sub privatekeyname {
	my $self = shift;
	my $name = $self->signame;
	sprintf 'K%s+%03d+%05d.private', $name, $self->algorithm, $self->keytag;
}

sub signame {
	my $self = shift;
	my $name = lc $self->{owner}->fqdn;
}


sub keylength {
	my $self = shift;

	my $keybin = $self->keybin || return undef;

	local $_ = algbyval( $self->{algorithm} );

	if (/^RSA/) {

		# Modulus length, see RFC 3110
		if ( my $exp_length = unpack 'C', $keybin ) {

			return ( length($keybin) - $exp_length - 1 ) << 3;

		} else {
			$exp_length = unpack 'x n', $keybin;
			return ( length($keybin) - $exp_length - 3 ) << 3;
		}

	} elsif (/^DSA/) {

		# Modulus length, see RFC 2536
		my $T = unpack 'C', $keybin;
		return ( $T << 6 ) + 512;

	} elsif (/^EC/) {

		return length($keybin) << 2;

	} else {
		return undef;
	}
}


sub keytag {
	my $self = shift;

	return 0 if ( $self->{flags} & 0xC000 ) == 0xC000;	# NULL KEY

	# RFC4034 Appendix B.1: most significant 16 bits of least significant 24 bits
	return unpack 'n', substr $self->keybin(), -3 if $self->{algorithm} == 1;

	# RFC4034 Appendix B
	return $self->{keytag} = do {
		my @kp = @{$self}{qw(flags protocol algorithm)};
		my $kb = $self->{keybin} || return 0;
		my $od = length($kb) & 1;
		my $ac = 0;
		$ac += $_ for unpack 'n*', pack "n C2 a* x$od", @kp, $kb;
		$ac += ( $ac >> 16 );
		$ac & 0xFFFF;
			}
}


sub zone {
	my $bit = 0x0100;
	for ( shift->{flags} ||= 0 ) {
		return $_ & $bit unless scalar @_;
		my $set = $_ | $bit;
		$_ = (shift) ? $set : ( $set ^ $bit );
		return $_ & $bit;
	}
}


sub revoke {
	my $bit = 0x0080;
	for ( shift->{flags} ||= 0 ) {
		return $_ & $bit unless scalar @_;
		my $set = $_ | $bit;
		$_ = (shift) ? $set : ( $set ^ $bit );
		return $_ & $bit;
	}
}


sub sep {
	my $bit = 0x0001;
	for ( shift->{flags} ||= 0 ) {
		return $_ & $bit unless scalar @_;
		my $set = $_ | $bit;
		$_ = (shift) ? $set : ( $set ^ $bit );
		return $_ & $bit;
	}
}


sub is_sep {				## historical
	my $self = shift;
	return $self->sep(@_) ? 1 : 0;
}

sub set_sep   { shift->is_sep(1); }	## historical
sub unset_sep { shift->is_sep(0); }	## historical
sub clear_sep { shift->is_sep(0); }	## historical

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name DNSKEY flags protocol algorithm publickey');

=head1 DESCRIPTION

Class for DNSSEC Key (DNSKEY) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 flags

    $flags = $rr->flags;
    $rr->flags( $flags );

Unsigned 16-bit number representing Boolean flags.

=head2 protocol

    $protocol = $rr->protocol;
    $rr->protocol( $protocol );

The 8-bit protocol number.  This field MUST have value 3.

=head2 algorithm

    $algorithm = $rr->algorithm;
    $rr->algorithm( $algorithm );

The 8-bit algorithm number describes the public key algorithm.

algorithm() may also be invoked as a class method or simple function
to perform mnemonic and numeric code translation.

=head2 key

    $key = $rr->key;
    $rr->key( $key );

The key field holds the public key material.
The format depends on the algorithm of the key being stored.

=head2 privatekeyname

    $privatekeyname = $rr->privatekeyname

Returns the name of the privatekey as it would be generated by
the BIND dnssec-keygen program. The format of that name being:

	K<fqdn>+<algorithm>+<keyid>.private

=head2 keylength

Returns the length (in bits) of the modulus calculated from the key text.

=head2 keytag

    print "keytag = ", $rr->keytag, "\n";

Returns the 16-bit numerical key tag of the key. (RFC2535 4.1.6)

=head2 zone

    $rr->zone(0);
    $rr->zone(1);

    if ( $rr->zone ) {
	...
    }

Boolean Zone key flag.

=head2 revoke

    $rr->revoke(0);
    $rr->revoke(1);

    if ( $rr->revoke ) {
	...
    }

Boolean Revoke flag.

=head2 sep

    $rr->sep(0);
    $rr->sep(1);

    if ( $rr->sep ) {
	...
    }

Boolean Secure Entry Point flag.


=head1 COPYRIGHT

Copyright (c)2003-2005 RIPE NCC.  Author Olaf M. Kolkman

All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of the author not be used
in advertising or publicity pertaining to distribution of the software
without specific prior written permission.

THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS; IN NO
EVENT SHALL AUTHOR BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL
DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
THIS SOFTWARE.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC4034, RFC3755

L<Algorithm Numbers|http://www.iana.org/assignments/dns-sec-alg-numbers>

=cut
