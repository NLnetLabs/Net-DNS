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


use integer;

use Carp;
use MIME::Base64;

use Net::DNS::Parameters;

require Net::DNS::DomainName;
require Net::DNS::ZoneFile;

require Digest::HMAC;
require Digest::MD5;
require Digest::SHA;

use constant ANY  => classbyname qw(ANY);
use constant TSIG => typebyname qw(TSIG);


{
	my %algbyname = (
		'HMAC-MD5.SIG-ALG.REG.INT' => 157,
		'HMAC-SHA1'		   => 161,
		'HMAC-SHA224'		   => 162,
		'HMAC-SHA256'		   => 163,
		'HMAC-SHA384'		   => 164,
		'HMAC-SHA512'		   => 165,
		);

	my %algbyval = reverse %algbyname;
	$algbyname{'HMAC-MD5'} = 157;
	$algbyname{'HMAC-SHA'} = 161;

	while ( my ( $key, $value ) = each %algbyname ) {
		$key =~ tr /A-Za-z0-9\000-\377/A-ZA-Z0-9/d;	# alphanumeric key
		$algbyname{$key} = $value;
	}

	sub algbyname {
		my $name = shift;
		my $key	 = $name;
		$key =~ tr /A-Za-z0-9\000-\377/A-ZA-Z0-9/d;	# alphanumeric key
		return 0 + $name unless $key =~ /\D/;		# accept algorithm number
		return $algbyname{$key};
	}

	sub algbyval {
		my $value = shift;
		return $algbyval{$value} || $value;
	}
}



sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
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
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	my $macbin = $self->macbin;
	unless ($macbin) {
		my ( $offset, undef, $packet ) = @_;

		my $sigdata = $self->sig_data($packet);		# form data to be signed
		$macbin = $self->macbin( $self->_mac_function($sigdata) );
		$self->original_id( $packet->header->id );
	}

	my $rdata = $self->{algorithm}->canonical;

	# Design decision: Use 32 bits, which will work until the end of time()!
	$rdata .= pack 'xxN n', $self->time_signed, $self->fudge;

	$rdata .= pack 'na*', length($macbin), $macbin;

	$rdata .= pack 'nn', $self->original_id, $self->{error} || 0;

	my $other = $self->other || '';
	$rdata .= pack 'na*', length($other), $other;

	return $rdata;
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	my @lines = (
		join( ' ', '; algorithm:  ', $self->algorithm ),
		join( ' ', '; time signed:', $self->time_signed, 'fudge:', $self->fudge ),
		join( ' ', '; original id:', $self->original_id ),
		join( ' ', ';', $self->error, $self->other || '' ) );
	join "\n", '', @lines;
}


sub defaults() {			## specify RR attribute default values
	my $self = shift;

	$self->algorithm(157);
	$self->class('ANY');
	$self->fudge(300);
}


sub encode {				## overide RR method
	my $self = shift;

	my $kname = $self->{owner}->encode();			# uncompressed key name
	my $rdata = eval { $self->encode_rdata(@_) } || '';
	return pack 'a* n2 N n a*', $kname, TSIG, ANY, 0, length $rdata, $rdata;
}

sub algorithm { &_algorithm; }

sub key {
	my $self = shift;

	$self->keybin( MIME::Base64::decode( join "", @_ ) ) if scalar @_;
	return MIME::Base64::encode( $self->keybin(), "" ) if defined wantarray;
}

sub keybin { &_keybin; }

sub time_signed {
	my $self = shift;

	$self->{time_signed} = 0 + shift if scalar @_;
	return $self->{time_signed} ||= time();
}

sub fudge {
	my $self = shift;

	$self->{fudge} = 0 + shift if scalar @_;
	return $self->{fudge} || 0;
}

sub mac {
	my $self = shift;

	$self->macbin( pack "H*", map { die "!hex!" if m/[^0-9A-Fa-f]/; $_ } join "", @_ ) if scalar @_;
	unpack "H*", $self->macbin() if defined wantarray;
}

sub macbin {
	my $self = shift;

	$self->{macbin} = shift if scalar @_;
	$self->{macbin} || "";
}

sub request_mac {
	my $self = shift;

	$self->request_macbin( pack "H*", map { die "!hex!" if m/[^0-9A-Fa-f]/; $_ } join "", @_ ) if scalar @_;
	unpack "H*", $self->request_macbin() if defined wantarray;
}

sub request_macbin {
	my $self = shift;

	$self->{request_macbin} = shift if scalar @_;
	$self->{request_macbin} || "";
}

sub continuation {
	my $self = shift;

	$self->{continuation} = shift if scalar @_;
	$self->{continuation} || 0;
}

sub original_id {
	my $self = shift;

	$self->{original_id} = 0 + shift if scalar @_;
	return $self->{original_id} || 0;
}

sub error {
	my $self = shift;
	$self->{error} = rcodebyname(shift) if scalar @_;
	rcodebyval( $self->{error} || 0 );
}

sub other {
	my $self = shift;

	$self->{other} = shift if scalar @_;
	$self->{other} || "";
}

sub other_data {&other}

sub sig_function {
	my $self = shift;

	return $self->{sig_function} unless scalar @_;
	$self->{sig_function} = shift;
}

sub sign_func { &sig_function; }	## historical

sub sig_data {
	my $self = shift;
	my $data = shift || '';

	if ( ref($data) ) {
		my $packet = $data if $data->isa('Net::DNS::Packet');
		die 'missing packet reference' unless $packet;

		my $original = $packet->{additional};
		my @unsigned = grep ref($_) ne ref($self), @$original;
		$packet->{additional} = \@unsigned;		# strip TSIG RR
		$data		      = $packet->data;
		$packet->{additional} = $original;		# reinstate TSIG RR
	}

	# Design decision: Use 32 bits, which will work until the end of time()!
	my $time = pack 'xxN n', $self->time_signed, $self->fudge;

	return pack 'a* a*', $data, $time if $self->continuation;

	# Insert the request MAC if present (used to validate responses).
	my $sigdata = '';
	my $req_mac = $self->request_macbin;
	$sigdata = pack 'na*', length($req_mac), $req_mac if $req_mac;

	$sigdata .= $data;

	my $kname = $self->{owner}->canonical;			# canonical key name
	$sigdata .= pack 'a* n N', $kname, ANY, 0;

	$sigdata .= $self->{algorithm}->canonical;		# canonical algorithm name

	$sigdata .= $time;

	$sigdata .= pack 'n', $self->{error} || 0;

	my $other = $self->other || '';
	$sigdata .= pack 'na*', length($other), $other;

	return $sigdata;
}

sub create {
	my $class = shift;
	my $karg  = shift;

	croak " Usage:	create $class( keyfile )\n\tcreate $class( keyname, key )" if ref($karg);

	if ( scalar(@_) == 1 ) {
		my $key = shift;				# ( keyname, key )
		my $new = new Net::DNS::RR(
			name => $karg,
			type => 'TSIG',
			key  => $key
			);
		return $new;

	} elsif ( $karg =~ /K([^+]+)[+0-9]+\.private$/ ) {	# ( keyfile, options )
		my $kname   = $1;
		my $keyfile = new Net::DNS::ZoneFile($karg);
		my ( $alg, $key );
		while ( my $line = $keyfile->_getline ) {
			for ($line) {
				( undef, $alg ) = split if /Algorithm:/;
				( undef, $key ) = split if /Key:/;
			}
		}
		return new Net::DNS::RR(
			name	  => $kname,
			type	  => 'TSIG',
			algorithm => $alg,
			key	  => $key,
			@_
			);

	} else {						# ( keyfile, options )
		my $keyfile = new Net::DNS::ZoneFile($karg);
		my $keyline = $keyfile->_getline;		# bad news: KEY is in Net::DNS::SEC
		my ( $kname, $c, $t, $f, $p, $algorithm, @key ) = split /\s+/, $keyline;
		croak 'key file incompatible with TSIG' unless "$c $t $f $p" eq 'IN KEY 512 3';
		my $key = join '', @key;
		return new Net::DNS::RR(
			name	  => $kname,
			type	  => 'TSIG',
			algorithm => $algorithm,
			key	  => $key,
			@_
			);
	}
}

sub verify {
	my $self = shift;
	my $data = shift;

	my $tsig = bless {%$self}, ref($self);
	if ( my $query = shift ) {
		croak 'Usage: $tsig->verify( $reply, $query )'
				unless ref($query) && $query->isa('Net::DNS::Packet');
		my $sigrr = $query->sigrr;
		$tsig->request_macbin( $sigrr->macbin );

		$self->error(17) && return 0 unless $tsig->name eq $sigrr->name;
		$self->error(17) && return 0 unless lc $tsig->algorithm eq lc $sigrr->algorithm;
	}

	unless ( abs( time() - $self->time_signed ) < $self->fudge ) {
		$self->error(18);				# bad time
		$self->other( pack 'xxN', time() );
		return 0;
	}

	$tsig->original_id( $self->original_id );
	$tsig->time_signed( $self->time_signed );

	my $sigdata = $tsig->sig_data($data);			# form data to be verified
	my $tsigmac = $tsig->macbin( $self->_mac_function($sigdata) );

	my $macbin = $self->macbin || return 0;			# possibly not signed
	my $maclen = length $macbin;
	my $minlen = length($tsigmac) >> 1;			# per RFC4635, 3.1
	$self->error(1) && return 0 if $maclen < 10;
	$self->error(1) && return 0 if $maclen < $minlen;
	$self->error(1) && return 0 if $maclen > length $tsigmac;

	$self->error(16) && return 0 unless $macbin eq substr $tsigmac, 0, $maclen;
	return 1;
}

sub vrfyerrstr {
	my $self = shift;
	return $self->error;
}


########################################


{
	my %digest = (
		'157' => ['Digest::MD5'],
		'161' => ['Digest::SHA'],
		'162' => ['Digest::SHA', 224, 64],
		'163' => ['Digest::SHA', 256, 64],
		'164' => ['Digest::SHA', 384, 128],
		'165' => ['Digest::SHA', 512, 128],
		);


	my %keytable;

	sub _algorithm {		## install sig function in key table
		my $self = shift;

		if ( my $algname = shift ) {

			unless ( my $digtype = algbyname($algname) ) {
				$self->{algorithm} = new Net::DNS::DomainName($algname);

			} else {
				$algname = algbyval($digtype);
				$self->{algorithm} = new Net::DNS::DomainName($algname);

				my ( $hash, @param ) = @{$digest{$digtype}};
				my ( undef, @block ) = @param;
				my $function = sub {
					my $digest = new $hash(@param);
					my $hmac = new Digest::HMAC( shift, $digest, @block );
					$hmac->add(shift);
					return $hmac->digest;
				};

				$self->sig_function($function);

				my $keyname = ( $self->{owner} || return )->canonical;
				$keytable{$keyname}{digest} = $function;
			}
		}

		return $self->{algorithm}->name if defined wantarray;
	}


	sub _keybin {			## install key in key table
		my $self = shift;
		croak 'Unauthorised access to TSIG key material denied' unless scalar @_;
		my $keyref = $keytable{$self->{owner}->canonical} ||= {};
		my $private = shift;	# closure keeps private key private
		$keyref->{key} = sub {
			my $function = $keyref->{digest};
			return &$function( $private, shift );
		};
		return undef;
	}


	sub _mac_function {		## apply keyed hash function to argument
		my $self = shift;

		my $keyref = $keytable{$self->{owner}->canonical} ||= {};
		$self->algorithm( $self->algorithm ) unless $keyref->{digest};
		$keyref->{digest} ||= $self->sig_function;
		my $function = $keyref->{key};
		return &$function(shift);
	}
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
    $rr->algorithm( $algorithm );

A domain name which specifies the name of the algorithm.

=head2 key

    $rr->key( $key );

Base64 representation of the key material.

=head2 keybin

    $rr->keybin( $keybin );

Binary representation of the key material.

=head2 time_signed

    $time_signed = $rr->time_signed;
    $rr->time_signed( $time_signed );

Signing time as the number of seconds since 1 Jan 1970 00:00:00 UTC.
The default signing time is the current time.

=head2 fudge

    $fudge = $rr->fudge;
    $rr->fudge( $fudge );

"fudge" represents the permitted error in the signing time.
The default fudge is 300 seconds.

=head2 mac

    $mac = $rr->mac;

Returns the message authentication code (MAC) as a string of hex
characters.  The programmer must call the Net::DNS::Packet data()
object method before this will return anything meaningful.

=cut


=head2 macbin

    $macbin = $rr->macbin;
    $rr->macbin( $macbin );

Binary message authentication code (MAC).

=head2 request_mac

    $request_mac = $rr->request_mac;
    $rr->request_mac( $request_mac );

Request message authentication code (MAC).

=head2 request_macbin

    $request_macbin = $rr->request_macbin;
    $rr->request_macbin( $request_macbin );

Binary request message authentication code.

=head2 continuation

     $tsig->continuation(1);

Flag which indicates continuation of a multi-message response.


=head2 original_id

    $original_id = $rr->original_id;
    $rr->original_id( $original_id );

The message ID from the header of the original packet.

=head2 error

     $rcode = $tsig->error;

Returns the RCODE covering TSIG processing.  Common values are
NOERROR, BADSIG, BADKEY, and BADTIME.  See RFC 2845 for details.


=head2 other

    $other = $rr->other;
    $rr->other( $other );

This field should be empty unless the error is BADTIME, in which
case it will contain the server time as the number of seconds since
1 Jan 1970 00:00:00 UTC.

=head2 sig_function

    sub signing_function {
	my ( $keybin, $data ) = @_;

	my $hmac = new Digest::HMAC( $keybin, 'Digest::MD5' );
	$hmac->add( $data );
	return $hmac->digest;
    }

    $tsig->sig_function( \&signing_function );

This sets the signing function to be used for this TSIG record.
The default signing function is HMAC-MD5.


=head2 sig_data

     $sigdata = $tsig->sig_data($packet);

Returns the packet packed according to RFC2845 in a form for signing. This
is only needed if you want to supply an external signing function, such as is
needed for TSIG-GSS.


=head2 create

    $tsig = create Net::DNS::RR::TSIG( $keyfile );

    $tsig = create Net::DNS::RR::TSIG( $keyfile,
					fudge => 300
					);

    $tsig = create Net::DNS::RR::TSIG( $keyname, $key );

Returns a TSIG RR constructed using the parameters in the specified
key file, which is assumed to have been generated by dnssec-keygen.

The two argument form is supported for backward compatibility.

=head2 verify

    $verify = $tsig->verify( $data );
    $verify = $tsig->verify( $packet );

    $verify = $tsig->verify( $reply, $query );

The boolean verify method will return true if the hash over the
packet data conforms to the data in the TSIG itself


=head1 TSIG Keys

TSIG keys are symmetric keys generated using dnssec-keygen:

	$ dnssec-keygen -a HMAC-MD5 -b 160 -n HOST <keyname>

	The key will be stored as a private and public keyfile pair
	K<keyname>+157+<keyid>.private and K<keyname>+157+<keyid>.key

    where
	<keyname> is the DNS name of the key.

	<keyid> is the (generated) numerical identifier used to
	distinguish this key.

Other algorithms may be substituted for HMAC-MD5 in the above example.

It is recommended that the keyname be globally unique and incorporate
the fully qualified domain names of the resolver and nameserver in
that order. It should be possible for more than one key to be in use
simultaneously between any such pair of hosts.

Although the formats differ, the private and public keys are identical
and both should be stored and handled as secret data.


=head1 Configuring BIND Nameserver

The following lines must be added to the /etc/named.conf file:

    key <keyname> {
	algorithm HMAC-MD5;
	secret "<keydata>";
    };

<keyname> is the name of the key chosen when the key was generated.

<keydata> is the key string extracted from the generated key file.


=head1 ACKNOWLEDGMENT

Most of the code in the Net::DNS::RR::TSIG module was contributed
by Chris Turbeville. 

Support for external signing functions was added by Andrew Tridgell.

TSIG verification, BIND keyfile handling and support for HMAC-SHA1,
HMAC-SHA224, HMAC-SHA256, HMAC-SHA384 and HMAC-SHA512 functions was
added by Dick Franks.


=head1 BUGS

A 32-bit representation of time is used, contrary to RFC2845 which
demands 48 bits.  This design decision will need to be reviewed
before the code stops working on 7 February 2106.


=head1 COPYRIGHT

Copyright (c)2002 Michael Fuhr. 

Portions Copyright (c)2002-2004 Chris Reinhardt.

Portions Copyright (c)2013 Dick Franks.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC2845, RFC4635

=cut
