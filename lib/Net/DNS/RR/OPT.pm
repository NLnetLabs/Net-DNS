package Net::DNS::RR::OPT;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base Net::DNS::RR;

=head1 NAME

Net::DNS::RR::OPT - DNS OPT resource record

=cut

use integer;
use Carp;

use Net::DNS::Parameters;

use constant CLASS_TTL_RDLENGTH => length pack 'n N n', (0) x 3;

use constant OPT => typebyname qw(OPT);


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $limit = $offset + $self->{rdlength};

	my $index = $offset - CLASS_TTL_RDLENGTH;		# OPT redefines class and TTL fields
	@{$self}{qw(size rcode version flags)} = unpack "\@$index n C2 n", $$data;
	@{$self}{rcode} = @{$self}{rcode} << 4;

	while ( $offset <= $limit - 4 ) {
		my ( $code, $length ) = unpack "\@$offset nn", $$data;
		$offset += 4;
		$self->option( $code, substr $$data, $offset, $length );
		$offset += $length;
	}

	croak('corrupt OPT data') unless $offset == $limit;	# more or less FUBAR
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	my $rdata = '';
	foreach ( $self->options ) {
		my $value = $self->option($_);
		$rdata .= pack 'nna*', $_, length($value), $value;
	}
	return $rdata;
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	croak 'zone file representation not defined for OPT';
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	croak 'zone file representation not defined for OPT' if shift;
}


sub defaults() {			## specify RR attribute default values
	my $self = shift;

	delete $self->{class};
}


sub encode {				## overide RR method
	my $self = shift;

	my $data = $self->encode_rdata;
	my $size = $self->size;
	my @xttl = ( $self->rcode >> 4, $self->version, $self->flags );
	pack 'C n n C2n n a*', 0, OPT, $size, @xttl, length($data), $data;
}

sub string {				## overide RR method
	my $self = shift;

	my $edns   = $self->version;
	my $flags  = sprintf '%04x', $self->flags;
	my $rcode  = $self->rcode;
	my $size   = $self->size;
	my @option = sort $self->options;
	my @lines  = join "\n;;\t\t",
			map sprintf( "%s\t%s", ednsoptionbyval($_), unpack 'H*', $self->option($_) ), @option;

	$rcode = 0 if $rcode < 16;				# weird: 1 .. 15 not EDNS codes!!
	$rcode = exists( $self->{rdlength} ) && $rcode ? "$rcode + [4-bits]" : rcodebyval($rcode);
	$rcode = 'BADVERS' if $rcode eq 'BADSIG';		# code 16 unambiguous here

	return <<"QQ";
;; EDNS version $edns
;;	flags:	$flags
;;	rcode:	$rcode
;;	size:	$size
;;	option: @lines
QQ
}

my $warned;

sub class {				## overide RR method
	my ( $self, $argument ) = @_;
	return &size() if $argument && $argument =~ /[^0-9]/;
	carp qq[Usage: OPT has no "class" attribute, please use "size()"] unless $warned++;
	&size;
}

sub ttl {				## overide RR method
	my $self = shift;
	my $mods = shift || return if scalar @_;
	carp qq[Usage: OPT has no "ttl" attribute, please use "flags()" and "rcode()"] unless $warned++;
	@{$self}{qw(rcode version flags)} = unpack 'C2 n', pack 'N', $mods if $mods;
	return pack 'C2 n', @{$self}{qw(rcode version flags)} if defined wantarray;
}

sub version {
	my $self = shift;

	$self->{version} = 0 + shift if scalar @_;
	return $self->{version} || 0;
}


sub size {
	my $self = shift;
	for ( $self->{size} ) {
		my $UDP_size = 0;
		( $UDP_size, $_ ) = ( shift || 0 ) if scalar @_;
		return $UDP_size > 512 ? ( $_ = $UDP_size ) : 512 unless $_;
		return $_ > 512 ? $_ : 512;
	}
}

sub rcode {
	my $self = shift;
	return $self->{rcode} || 0 unless scalar @_;
	delete $self->{rdlength};				# (ab)used to signal incomplete value
	my $val = shift || 0;
	$val = 0 if $val < 16;					# discard non-EDNS rcodes 1 .. 15
	$self->{rcode} = $val if $val or defined $self->{rcode};
	return $val;
}

sub flags {
	my $self = shift;
	return $self->{flags} || 0 unless scalar @_;
	my $val = shift;
	$self->{flags} = $val if $val or defined $self->{flags};
	return $val;
}

sub options {
	my $self = shift;
	my $options = $self->{option} || {};
	return keys %$options;
}

sub option {
	my $self = shift;

	my $options = $self->{option} || {};
	while ( scalar @_ ) {
		my $option = shift;
		my $number = ednsoptionbyname($option);
		return $options->{$number} unless scalar @_;
		my $value = shift;
		delete $options->{$number} unless defined $value;
		$options = $self->{option} ||= {};
		$options->{$number} = $value if defined $value;
	}
}

sub defined {
	my $self = shift;

	foreach (qw(size flags rcode option)) {
		return 1 if defined $self->{$_};
	}
	return 0;
}

sub do {				## historical
	my $self = shift;
	carp qq[Deprecated method: please use packet->header->do()] unless $warned++;
	$self->{flags} & 0x8000;
}

sub clear_do {				## historical
	my $self = shift;
	carp qq[Deprecated method: please use packet->header->do(0)] unless $warned++;
	$self->{flags} = ( ~0x8000 & $self->{flags} );
}

sub set_do {				## historical
	my $self = shift;
	carp qq[Deprecated method: please use packet->header->do(1)] unless $warned++;
	$self->{flags} = ( 0x8000 | $self->{flags} );
}

sub ednsversion	  {&version}
sub ednsflags	  {&flags}
sub extendedrcode {&rcode}

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $opt = new Net::DNS::RR(
	type	=> "OPT",  
	flags	=> 0x8000,	# extended flags
	rcode	=> 0,		# extended RCODE
	size	=> 1280,	# UDP payload size
	);

=head1 DESCRIPTION

EDNS OPT pseudo resource record.

The OPT record supports EDNS protocol extensions and is not intended
to be created, accessed or modified directly by user applications.

All access to EDNS features is performed indirectly by operations on
the packet header.  The underlying mechanism is entirely hidden from
the user.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 version

    $version = $rr->version;
    $rr->version( $version );

The version of EDNS used by this OPT record.

=head2 size

	$size = $packet->edns->size;
	$more = $packet->edns->size(1280);

size() advertises the maximum size (octets) of UDP packet that can be
reassembled in the network stack of the originating host.

=head2 rcode

	$extended_rcode	  = $packet->header->rcode;
	$incomplete_rcode = $packet->edns->rcode;

The 12 bit extended RCODE. The most significant 8 bits reside in
the OPT record.  The least significant 4 bits can only be obtained
from the packet header.

=head2 flags

	$edns_flags = $packet->edns->flags;

	$do = $packet->header->do;
	$packet->header->do(1);

16 bit field containing EDNS extended header flags.

=head2 Options

	@option = $packet->edns->options;

	$octets = $packet->edns->option($option_code);

	$packet->edns->option( NSID => 'value' );
	$packet->edns->option( 3    => 'value' );

When called in a list context, options() returns a list of option codes
found in the OPT record.

When called with a single argument, option() returns the octet string
corresponding to the specified option. The function value is undefined
if the specified option is absent.

Options can be changed by providing an argument list containing one or
more (name => value) pairs to be added or modified. The effect of such
changes is cumulative. An option is deleted if the value is undefined.


=head1 COPYRIGHT

Copyright (c)2001,2002	RIPE NCC.  Author Olaf M. Kolkman.

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

Portions Copyright (c)2012 Dick Franks.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC2671 Section 4

=cut
