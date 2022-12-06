package Net::DNS::RR::OPT;

use strict;
use warnings;
our $VERSION = (qw$Id$)[2];

use base qw(Net::DNS::RR);


=head1 NAME

Net::DNS::RR::OPT - DNS OPT resource record

=cut

use integer;

use Carp;
use Net::DNS::Parameters qw(:rcode :ednsoption);

use constant CLASS_TTL_RDLENGTH => length pack 'n N n', (0) x 3;

use constant OPT => Net::DNS::Parameters::typebyname qw(OPT);

require Net::DNS::DomainName;
require Net::DNS::RR::A;
require Net::DNS::RR::AAAA;
require Net::DNS::Text;


sub _decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $index = $offset - CLASS_TTL_RDLENGTH;		# OPT redefines class and TTL fields
	@{$self}{qw(size rcode version flags)} = unpack "\@$index n C2 n", $$data;
	@{$self}{rcode} = @{$self}{rcode} << 4;
	delete @{$self}{qw(class ttl)};

	my $limit = $offset + $self->{rdlength} - 4;

	while ( $offset <= $limit ) {
		my ( $code, $length ) = unpack "\@$offset nn", $$data;
		my $value = unpack "\@$offset x4 a$length", $$data;
		$self->{option}{$code} = $value;
		$offset += $length + 4;
	}
	return;
}


sub _encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	my $option = $self->{option} || {};
	return join '', map { pack( 'nna*', $_, length $option->{$_}, $option->{$_} ) } keys %$option;
}


sub encode {				## overide RR method
	my $self = shift;

	my $data = $self->_encode_rdata;
	my $size = $self->size;
	my @xttl = ( $self->rcode >> 4, $self->version, $self->flags );
	return pack 'C n n C2n n a*', 0, OPT, $size, @xttl, length($data), $data;
}


sub string {				## overide RR method
	my $self = shift;

	my $edns   = $self->version;
	my $flags  = sprintf '%04x', $self->flags;
	my $rcode  = $self->rcode;
	my $size   = $self->size;
	my @option = map { join( "\n;;\t\t\t\t", $self->_format_option($_) ) } $self->options;
	my @format = join "\n;;\t\t", @option;

	$rcode = 0 if $rcode < 16;				# weird: 1 .. 15 not EDNS codes!!

	my $rc = exists( $self->{rdlength} ) && $rcode ? "$rcode + [4-bits]" : rcodebyval($rcode);

	$rc = 'BADVERS' if $rcode == 16;			# code 16 unambiguous here

	return <<"QQ";
;; EDNS version $edns
;;	flags:	$flags
;;	rcode:	$rc
;;	size:	$size
;;	option: @format
QQ
}


sub class {				## overide RR method
	my $self = shift;
	$self->_deprecate(qq[please use "size()"]);
	return $self->size(@_);
}

sub ttl {				## overide RR method
	my $self = shift;
	$self->_deprecate(qq[please use "flags()" or "rcode()"]);
	my @rcode = map { unpack( 'C',	 pack 'N', $_ ) } @_;
	my @flags = map { unpack( 'x2n', pack 'N', $_ ) } @_;
	return pack 'C2n', $self->rcode(@rcode), $self->version, $self->flags(@flags);
}


sub version {
	my $self = shift;

	$self->{version} = 0 + shift if scalar @_;
	return $self->{version} || 0;
}


sub size {
	my $self = shift;
	$self->{size} = shift if scalar @_;
	return ( $self->{size} || 0 ) > 512 ? $self->{size} : 512;
}


sub rcode {
	my $self = shift;
	return $self->{rcode} || 0 unless scalar @_;
	delete $self->{rdlength};				# (ab)used to signal incomplete value
	my $val = shift || 0;
	return $self->{rcode} = $val < 16 ? 0 : $val;		# discard non-EDNS rcodes 1 .. 15
}


sub flags {
	my $self = shift;
	$self->{flags} = shift if scalar @_;
	return $self->{flags} || 0;
}


sub options {
	my ($self) = @_;
	my $option = $self->{option} || {};
	my @option = sort { $a <=> $b } keys %$option;
	return @option;
}

sub option {
	my $self   = shift;
	my $number = ednsoptionbyname(shift);
	return $self->_get_option($number) unless scalar @_;
	return $self->_set_option( $number, @_ );
}


########################################

sub _format_option {
	my ( $self, $number ) = @_;
	my $option  = ednsoptionbyval($number);
	my $options = $self->{option} || {};
	my $payload = $options->{$number};
	return () unless defined $payload;
	my $package = join '::', __PACKAGE__, $option;
	$package =~ s/-/_/g;
	my @element = $package->can('_image') ? eval { $package->_image($payload) } : ();
	@element = unpack( 'H*', $payload ) unless scalar(@element);
	my $protect = pop(@element);
	return Net::DNS::RR::_wrap( "$option\t=> (", map( {"$_,"} @element ), "$protect )" );
}


sub _get_option {
	my ( $self, $number ) = @_;

	my $options = $self->{option} || {};
	my $payload = $options->{$number};
	return $payload unless wantarray;
	return ()	unless $payload;
	my $package = join '::', __PACKAGE__, ednsoptionbyval($number);
	$package =~ s/-/_/g;
	my @element = $package->can('_decompose') ? eval { $package->_decompose($payload) } : ();
	return scalar(@element) ? @element : ( 'OPTION-DATA' => $payload );
}


sub _set_option {
	my ( $self, $number, @value ) = @_;

	my $options = $self->{option} ||= {};
	delete $options->{$number};

	my $arg = $value[0];
	return unless defined $arg;
	for ($arg) {
		@value = @$_ if ref($_) eq 'ARRAY';
		@value = %$_ if ref($_) eq 'HASH';
	}

	return $options->{$number} = $value[1] if $value[0] =~ /^OPTION-DATA$/i;

	my $option  = ednsoptionbyval($number);
	my $package = join '::', __PACKAGE__, $option;
	$package =~ s/-/_/g;

	if ( $package->can('_compose') ) {
		return eval { $options->{$number} = $package->_compose(@value) } if ref($arg);
		return eval { $options->{$number} = $package->_compose(@value) } if scalar(@value) > 1;
	}

	my $value = shift @value;
	croak "unable to compose option $number" if scalar(@value);
	return $options->{$number} = $value;
}


sub _specified {
	my $self = shift;
	return scalar grep { $self->{$_} } qw(size flags rcode option);
}


## no critic ProhibitMultiplePackages
package Net::DNS::RR::OPT::DAU;					# RFC6975

sub _compose {
	my ( $class, @argument ) = @_;
	return pack 'C*', @argument;
}

sub _decompose { return unpack 'C*', pop @_; }

sub _image { return &_decompose; }


package Net::DNS::RR::OPT::DHU;					# RFC6975
our @ISA = qw(Net::DNS::RR::OPT::DAU);

package Net::DNS::RR::OPT::N3U;					# RFC6975
our @ISA = qw(Net::DNS::RR::OPT::DAU);


package Net::DNS::RR::OPT::CLIENT_SUBNET;			# RFC7871

my %family = qw(0 Net::DNS::RR::AAAA	1 Net::DNS::RR::A	2 Net::DNS::RR::AAAA);
my @field8 = qw(FAMILY SOURCE-PREFIX-LENGTH SCOPE-PREFIX-LENGTH ADDRESS);

sub _compose {
	my %argument = ( map( ( $_ => 0 ), @field8 ), 'class', @_ );
	my $address  = bless( {}, $family{$argument{FAMILY}} )->address( $argument{ADDRESS} );
	my $bitmask  = $argument{'SOURCE-PREFIX-LENGTH'};
	return pack "a* B$bitmask", pack( 'nC2', @argument{@field8} ), unpack 'B*', $address;
}

sub _decompose {
	my %hash;
	@hash{@field8} = unpack 'nC2a*', pop @_;
	( $hash{FAMILY} ) = grep $family{$_}, $hash{FAMILY}, 0;
	$hash{ADDRESS} = bless( {address => $hash{ADDRESS}}, $family{$hash{FAMILY}} )->address;
	return map( ( $_ => $hash{$_} ), @field8 );
}

sub _image {
	my %hash = &_decompose;
	return map "$_ => $hash{$_}", @field8;
}


package Net::DNS::RR::OPT::EXPIRE;				# RFC7314

sub _compose { return pack 'N', pop @_; }

sub _decompose { return ( 'EXPIRE-TIMER' => unpack( 'N', pop @_ ) ); }

sub _image { return join ' => ', &_decompose; }


package Net::DNS::RR::OPT::COOKIE;				# RFC7873

my @field10 = qw(CLIENT-COOKIE SERVER-COOKIE);

sub _compose {
	my %argument = ( map( ( $_ => '' ), @field10 ), 'class', @_ );
	return pack 'a8a*', @argument{@field10};
}

sub _decompose {
	my %hash;
	@hash{@field10} = unpack 'a8a*', pop @_;
	return map( ( $_ => $hash{$_} ), @field10 );
}

sub _image {
	my ( @list, @image ) = &_decompose;
	while ( my $key = shift @list ) {
		push @image, join ' => ', $key, unpack 'H*', shift @list;
	}
	return @image;
}


package Net::DNS::RR::OPT::TCP_KEEPALIVE;			# RFC7828

sub _compose { return pack 'n', pop @_; }

sub _decompose { return ( 'TIMEOUT' => unpack( 'n', pop @_ ) ); }

sub _image { return join ' => ', &_decompose; }


package Net::DNS::RR::OPT::PADDING;				# RFC7830

sub _compose {
	my $size = pop @_;
	return pack "x$size";
}

sub _decompose { return ( 'OPTION-LENGTH' => length pop @_ ); }

sub _image { return join ' => ', &_decompose; }


package Net::DNS::RR::OPT::CHAIN;				# RFC7901

sub _compose { return Net::DNS::DomainName->new( pop @_ )->encode; }

sub _decompose {
	my $payload = pop @_;
	return ( 'CLOSEST-TRUST-POINT' => Net::DNS::DomainName->decode( \$payload )->string );
}

sub _image { return join ' => ', &_decompose; }


package Net::DNS::RR::OPT::KEY_TAG;				# RFC8145

sub _compose {
	my ( $class, @argument ) = @_;
	return pack 'n*', @argument;
}

sub _decompose { return unpack 'n*', pop @_; }

sub _image { return &_decompose; }


package Net::DNS::RR::OPT::EXTENDED_ERROR;			# RFC8914

my @field15 = qw(INFO-CODE EXTRA-TEXT);

sub _compose {
	my %argument = ( map( ( $_ => '' ), @field15 ), 'class', @_ );
	my ( $code, $extra ) = @argument{@field15};
	return pack 'na*', 0 + $code, Net::DNS::Text->new($extra)->raw;
}

sub _decompose {
	my ( $code, $extra ) = unpack 'na*', pop @_;
	my @error = grep {defined} $Net::DNS::Parameters::dnserrorbyval{$code};
	return ('INFO-CODE' => $code,
		map( ( 'DNS-ERROR' => qq("$_") ), @error ),
		'EXTRA-TEXT' => Net::DNS::Text->decode( \$extra, 0, length $extra )->string
		);
}

sub _image {
	my ( @list, @image ) = &_decompose;
	while ( my $key = shift @list ) {
		push @image, join ' => ', $key, shift @list;
	}
	return @image;
}


package Net::DNS::RR::OPT::REPORT_CHANNEL;			# draft-ietf-dnsop-dns-error-reporting
$Net::DNS::Parameters::ednsoptionbyval{65023} = 'REPORT-CHANNEL';	# experimental/private use

sub _compose { return Net::DNS::DomainName->new( pop @_ )->encode; }

sub _decompose {
	my $payload = pop @_;
	return ( 'AGENT-DOMAIN' => Net::DNS::DomainName->decode( \$payload )->string );
}

sub _image { return join ' => ', &_decompose; }

########################################


1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $packet = Net::DNS::Packet->new( ... );

    $packet->header->do(1);			# extended flag

    $packet->edns->size(1280);			# UDP payload size

    $packet->edns->option( DAU		    => [8, 10, 13, 14, 15, 16] );
    $packet->edns->option( 'EXTENDED-ERROR' => {'INFO-CODE'   => 123} );
    $packet->edns->option( 65534	    => {'OPTION-DATA' => 'rawbytes'} );

    $packet->edns->print;

    ;; EDNS version 0
    ;;	    flags:  8000
    ;;	    rcode:  NOERROR
    ;;	    size:   1280
    ;;	    option: DAU	    => ( 8, 10, 13, 14, 15, 16 )
    ;;		    EXTENDED-ERROR  => ( INFO-CODE => 123, EXTRA-TEXT => "" )
    ;;		    65534   => ( 7261776279746573 )




=head1 DESCRIPTION

EDNS OPT pseudo resource record.

The OPT record supports EDNS protocol extensions and is not intended to be
created, accessed or modified directly by user applications.

All EDNS features are performed indirectly by operations on the objects
returned by the $packet->header and $packet->edns creator methods.
The underlying mechanisms are entirely hidden from the user.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 version

	$version = $packet->edns->version;

The version of EDNS supported by this OPT record.

=head2 size

	$size = $packet->edns->size;
	$more = $packet->edns->size(1280);

size() advertises the maximum size (octets) of UDP packet that can be
reassembled in the network stack of the originating host.

=head2 rcode

	$extended_rcode	  = $packet->header->rcode;
	$incomplete_rcode = $packet->edns->rcode;

The 12 bit extended RCODE. The most significant 8 bits reside in the OPT
record. The least significant 4 bits can only be obtained from the packet
header.

=head2 flags

	$edns_flags = $packet->edns->flags;

	$do = $packet->header->do;
	$packet->header->do(1);

16 bit field containing EDNS extended header flags.

=head2 options, option

	@option = $packet->edns->options;

	$octets = $packet->edns->option($option_code);

	$packet->edns->option( COOKIE => $octets );
	$packet->edns->option( 10     => $octets );

When called in a list context, options() returns a list of option codes
found in the OPT record.

When called in a scalar context with a single argument,
option() returns the uninterpreted octet string
corresponding to the specified option.
The method returns undef if the specified option is absent.

Options can be added or replaced by providing the (name => value) pair.
The option is deleted if the value is undefined.

When option() is called in a list context with a single argument,
the returned values provide a structured interpretation
appropriate to the specified option.

For example:

	@algorithms = $packet->edns->option('DAU');


For some options, a hash table is more appropriate:

	%hash_table = $packet->edns->option(15);
	$info_code  = $hash_table{'INFO-CODE'};
	$extra_text = $hash_table{'EXTRA-TEXT'};


Similar forms of array or hash syntax may be used to construct the
option value:

	$packet->edns->option( DAU => [8, 10, 13, 14, 15, 16] );

	$packet->edns->option( EXTENDED-ERROR => {'INFO-CODE'  => 123,
						  'EXTRA-TEXT' => ""} );


=head1 COPYRIGHT

Copyright (c)2001,2002 RIPE NCC.  Author Olaf M. Kolkman.

Portions Copyright (c)2012,2017-2022 Dick Franks.

All rights reserved.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 LICENSE

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted, provided
that the original copyright notices appear in all copies and that both
copyright notice and this permission notice appear in supporting
documentation, and that the name of the author not be used in advertising
or publicity pertaining to distribution of the software without specific
prior written permission.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC6891, RFC3225

=cut
