package Net::DNS::RR::SVCB;

#
# $Id$
#
our $VERSION = (qw$LastChangedRevision$)[1];


use strict;
use warnings;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::SVCB - DNS SVCB resource record

=cut


use integer;

use Carp;
use MIME::Base64;
use Net::DNS::DomainName;
use Net::DNS::RR::A;
use Net::DNS::RR::AAAA;
use Net::DNS::Text;


sub _decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $limit = $offset + $self->{rdlength};
	$self->{SvcPriority} = unpack( "\@$offset n", $$data );
	( $self->{TargetName}, $offset ) = decode Net::DNS::DomainName( $data, $offset + 2 );

	my $params = $self->{SvcParams} = {};
	while ( $offset < $limit ) {
		my ( $key, $size ) = unpack( 'n2', substr $$data, $offset, 4 );
		$params->{$key} = substr $$data, $offset + 4, $size;
		$offset += 4 + $size;
	}
	die $self->type . ': RDATA does not match declared length' unless $offset == $limit;
	$self->_post_parse;
}


sub _encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	my ($params) = grep defined, $self->{SvcParams}, {};
	my @params;
	foreach ( sort { $a <=> $b } keys %$params ) {
		my $value = $params->{$_};
		next unless defined $value;
		push @params, pack( 'n2a*', $_, length($value), $value );
	}
	pack 'n a* a*', $self->{SvcPriority}, $self->{TargetName}->encode, join '', @params;
}


sub _format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	my ($params) = grep defined, $self->{SvcParams}, {};
	my @keys = keys %$params;
	return ( $self->{SvcPriority}, $self->{TargetName}->string ) unless scalar @keys;

	my @rdata  = unpack 'H4', pack 'n', $self->{SvcPriority};
	my $target = $self->{TargetName}->encode();
	my $length = 2 + length $target;
	my @target = split /(\S{32})/, unpack 'H*', $target;
	$target[$#target] .= join ' ', "\t;", $self->{TargetName}->string if $length > 3;
	push @rdata, $length > 18 ? "\n" : (), @target, "\n";

	foreach ( sort { $a <=> $b } @keys ) {
		my $value = $params->{$_};
		next unless defined $value;
		push @rdata, unpack 'H4H4', pack( 'n2', $_, length $value );
		push @rdata, split /(\S{32})/, unpack 'H*', $value;
		push @rdata, "\n";
		$length += 4 + length $value;
	}
	return ( '\\#', $length, @rdata );
}


sub _parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->svcpriority(shift);
	$self->targetname(shift);

	while ( my $attribute = shift ) {
		for ($attribute) {
			my @argument;
			if (/=(.*)$/) {
				for ( my $rhs = length($1) ? $1 : shift ) {
					s/^(["'])(.*)\1$/$2/;	# strip paired quotes
					s/\\,/\\044/g;		# disguise escaped comma
					@argument = split /,/;	# potentially multi-valued
				}
			}

			s/[-]/_/g;				# extract attribute identifier
			m/^([^=]+)/;
			$self->$1(@argument);
		}
	}
}


sub _post_parse {			## parser post processing
	my $self = shift;

	my $params = $self->{SvcParams} || return;
	my %unique;
	my @unique = grep !$unique{$_}++, unpack 'n*', $params->{0} || return;
	map croak( $self->type . qq(: mandatory "key$_" not defined) ), grep !defined( $params->{$_} ), @unique;
	croak( $self->type . qq(: unexpected "key0" in mandatory list) ) if $unique{0};
	map croak( $self->type . qq(: duplicate "key$_" in mandatory list) ), grep --$unique{$_}, @unique;
}


sub _defaults {				## specify RR attribute default values
	my $self = shift;

	$self->_parse_rdata(qw(0 .));
}


sub svcpriority {
	my $self = shift;

	$self->{SvcPriority} = 0 + shift if scalar @_;
	$self->{SvcPriority} || 0;
}


sub targetname {
	my $self = shift;

	$self->{TargetName} = new Net::DNS::DomainName(shift) if scalar @_;
	$self->{TargetName}->name if $self->{TargetName};
}


########################################


sub _raw {
	join '', map sprintf( '\\%03u', $_ ), unpack 'C*', shift;
}

sub _base64 {
	_raw( MIME::Base64::decode(shift) );
}

sub _integer16 {
	_raw( pack 'n*', @_ );
}

sub _ipv4 {
	_raw( join '', map bless( {}, 'Net::DNS::RR::A' )->address($_), @_ );
}

sub _ipv6 {
	_raw( join '', map bless( {}, 'Net::DNS::RR::AAAA' )->address($_), @_ );
}

sub _string {
	_raw( join '', map Net::DNS::Text->new($_)->encode(), @_ );
}


my %keybyname = (
	mandatory	  => 0,
	alpn		  => 1,
	'no-default-alpn' => 2,
	port		  => 3,
	ipv4hint	  => 4,
	echconfig	  => 5,
	ipv6hint	  => 6,
	);


sub mandatory {				## mandatory=1,2,...
	my $self = shift;					# uncoverable pod
	my @keys = grep defined, map $keybyname{lc $_}, @_;
	push @keys, map m/^key(\d+)/i ? $1 : (), @_;
	$self->key0( _integer16( sort { $a <=> $b } @keys ) );
}

sub alpn {				## alpn=h3-29,h3-28,h3-27,h2
	my $self = shift;					# uncoverable pod
	$self->key1( _string(@_) );
}

sub no_default_alpn {			## no-default-alpn
	shift->key2('');					# uncoverable pod
}

sub port {				## port=1234
	my $self = shift;					# uncoverable pod
	$self->key3( _integer16(shift) );
}

sub ipv4hint {				## ipv4hint=192.0.2.1,...
	my $self = shift;					# uncoverable pod
	$self->key4( _ipv4(@_) );
}

sub echconfig {				## echconfig=base64string
	my $self = shift;					# uncoverable pod
	$self->key5( _base64(shift) );
}

sub ipv6hint {				## ipv6hint=2001:DB8::1,...
	my $self = shift;					# uncoverable pod
	$self->key6( _ipv6(@_) );
}


our $AUTOLOAD;

sub AUTOLOAD {				## Default method
	my $self = shift;
	my ($method) = reverse split /::/, $AUTOLOAD;

	my $inherit = join '::', 'SUPER', $method;
	return $self->$inherit(@_) unless $method =~ /^key(\d+)$/i;
	my $key = $1;

	my ($params) = grep defined, $self->{SvcParams}, {};
	return _raw( $params->{$key} ) unless scalar @_;	# $value = keyNN();

	my $arg = shift;					# keyNN($value);
	croak qq["$method" called with multiple arguments] if scalar @_;

	$params->{$key} = defined($arg) ? Net::DNS::Text->new($arg)->raw : undef;
	$self->{SvcParams} = $params;
	return undef;
}


1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    use Net::DNS;
    $rr = new Net::DNS::RR('name HTTPS SvcPriority TargetName alpn=h3-29,h3-28,h3-27,h2 ...');

=head1 DESCRIPTION

DNS Service Binding (SVCB) resource record

Service binding and parameter specification
via the DNS (SVCB and HTTPS RRs)

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 SvcPriority

    $svcpriority = $rr->svcpriority;
    $rr->svcpriority( $svcpriority );

The priority of this record
(relative to others, with lower values preferred). 
A value of 0 indicates AliasMode.

=head2 TargetName

    $targetname = $rr->targetname;
    $rr->targetname( $targetname );

The domain name of either the alias target
(for AliasMode) or the alternative endpoint (for ServiceMode).


=head1 COPYRIGHT

Copyright (c)2020 Dick Franks. 

All rights reserved.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 LICENSE

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted, provided
that the above copyright notice appear in all copies and that both that
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

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, draft-ietf-dnsop-svcb-https-01

=cut
