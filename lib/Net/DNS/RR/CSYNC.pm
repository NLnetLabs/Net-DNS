package Net::DNS::RR::CSYNC;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::CSYNC - DNS CSYNC resource record

=cut


use integer;

use Net::DNS::Parameters;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $limit = $offset + $self->{rdlength};
	@{$self}{qw(SOAserial flags)} = unpack "\@$offset Nn", $$data;
	$offset += 6;
	$self->{typebm} = substr $$data, $offset, $limit - $offset;
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless $self->{typebm};
	pack 'N n a*', $self->SOAserial, $self->flags, $self->{typebm};
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{typebm};
	my @rdata = $self->SOAserial, $self->flags, $self->typelist;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->SOAserial(shift);
	$self->flags(shift);
	$self->typelist(@_);
}


sub SOAserial {
	my $self = shift;

	$self->{SOAserial} = 0 + shift if scalar @_;
	return $self->{SOAserial} || 0;
}


sub soaserial {&SOAserial}


sub flags {
	my $self = shift;

	$self->{flags} = 0 + shift if scalar @_;
	return $self->{flags} || 0;
}


sub immediate {
	my $bit = 0x0001;
	for ( shift->{flags} ||= 0 ) {
		return $_ & $bit unless scalar @_;
		my $set = $_ | $bit;
		$_ = (shift) ? $set : ( $set ^ $bit );
		return $_ & $bit;
	}
}


sub soaminimum {
	my $bit = 0x0002;
	for ( shift->{flags} ||= 0 ) {
		return $_ & $bit unless scalar @_;
		my $set = $_ | $bit;
		$_ = (shift) ? $set : ( $set ^ $bit );
		return $_ & $bit;
	}
}


sub typelist {
	my $self = shift;

	$self->{typebm} = &_type2bm if scalar @_;

	my @type = defined wantarray ? &_bm2type( $self->{typebm} ) : ();
	return wantarray ? (@type) : "@type";
}


########################################

sub _type2bm {
	my @typearray;
	foreach my $typename ( map split( /\s+/, $_ ), @_ ) {
		next unless $typename;
		my $typenum = typebyname( uc $typename );
		my $window  = $typenum >> 8;
		next unless $window or $typenum < 128;		# skip meta type
		next if $typenum == 41;				# skip meta type
		my $bitnum = $typenum & 255;
		my $octet  = $bitnum >> 3;
		my $bit	   = $bitnum & 7;
		$typearray[$window][$octet] |= 0x80 >> $bit;
	}

	my $bitmap;
	my $window = 0;
	foreach (@typearray) {
		if ( my $pane = $typearray[$window] ) {
			my @content = map $_ || 0, @$pane;
			$bitmap .= pack 'CC C*', $window, scalar(@content), @content;
		}
		$window++;
	}

	return $bitmap || '';
}


sub _bm2type {
	my $bitmap = shift || '';
	my $index  = 0;
	my $limit  = length $bitmap;
	my @typelist;

	while ( $index < $limit ) {
		my ( $block, $size ) = unpack "\@$index C2", $bitmap;
		my @octet = unpack "\@$index xxC$size", $bitmap;
		$index += $size + 2;
		my $typenum = $block << 8;
		foreach my $octet (@octet) {
			$typenum += 8;
			my $i = $typenum;
			while ($octet) {
				--$i;
				push @typelist, typebyval($i) if $octet & 1;
				$octet = $octet >> 1;
			}
		}
	}

	return sort @typelist;
}


1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name CSYNC SOAserial flags typelist');

=head1 DESCRIPTION

Class for DNSSEC CSYNC resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 SOAserial

    $SOAserial = $rr->SOAserial;
    $rr->SOAserial( $SOAserial );

The SOA Serial field contains a copy of the 32-bit SOA serial number from
the child zone.

=head2 flags

    $flags = $rr->flags;
    $rr->flags( $flags );

The flags field contains 16 bits of boolean flags that define operations
which affect the processing of the CSYNC record.

=over 4

=item immediate

 $rr->immediate(1);

 if ( $rr->immediate ) {
	...
 }


If not set, a parental agent must not process the CSYNC record until
the zone administrator approves the operation through an out-of-band
mechanism.

=back

=over 4

=item soaminimum

 $rr->soaminimum(1);

 if ( $rr->soaminimum ) {
	...
 }

If set, a parental agent querying child authoritative servers must not
act on data from zones advertising an SOA serial number less than the
SOAserial value.

=back

=head2 typelist

    @typelist = $rr->typelist;
    $typelist = $rr->typelist;

The type list indicates the record types to be processed by the parental
agent. When called in scalar context, the list is interpolated into a
string.


=head1 COPYRIGHT

Copyright (c)2015 Dick Franks

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

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC7477

=cut
