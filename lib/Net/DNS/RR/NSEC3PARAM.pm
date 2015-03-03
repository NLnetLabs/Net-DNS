package Net::DNS::RR::NSEC3PARAM;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::NSEC3PARAM - DNS NSEC3PARAM resource record

=cut


use integer;
use warnings;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $size = unpack "\@$offset x4 C", $$data;
	@{$self}{qw(algorithm flags iterations saltbin)} = unpack "\@$offset CCnx a$size", $$data;
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless $self->{algorithm};
	my $salt = $self->{saltbin};
	pack 'CCnCa*', @{$self}{qw(algorithm flags iterations)}, length($salt), $salt;
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{algorithm};
	join ' ', $self->algorithm, $self->flags, $self->iterations, $self->salt || '-';
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->algorithm(shift);
	$self->flags(shift);
	$self->iterations(shift);
	my $salt = shift;
	$self->salt($salt) unless $salt eq '-';
}


sub algorithm {
	my $self = shift;

	$self->{algorithm} = 0 + shift if scalar @_;
	return $self->{algorithm} || 0;
}


sub flags {
	my $self = shift;

	$self->{flags} = 0 + shift if scalar @_;
	return $self->{flags} || 0;
}


sub iterations {
	my $self = shift;

	$self->{iterations} = 0 + shift if scalar @_;
	return $self->{iterations} || 0;
}


sub salt {
	my $self = shift;

	$self->saltbin( pack "H*", map { die "!hex!" if m/[^0-9A-Fa-f]/; $_ } join "", @_ ) if scalar @_;
	unpack "H*", $self->saltbin() if defined wantarray;
}


sub saltbin {
	my $self = shift;

	$self->{saltbin} = shift if scalar @_;
	$self->{saltbin} || "";
}


########################################

sub hashalgo {&algorithm}		## historical

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name NSEC3PARAM algorithm flags iterations salt');

=head1 DESCRIPTION

Class for DNSSEC NSEC3PARAM resource records.

The NSEC3PARAM RR contains the NSEC3 parameters (hash algorithm,
flags, iterations and salt) needed to calculate hashed ownernames.

The presence of an NSEC3PARAM RR at a zone apex indicates that the
specified parameters may be used by authoritative servers to choose
an appropriate set of NSEC3 records for negative responses.

The NSEC3PARAM RR is not used by validators or resolvers.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 algorithm

    $algorithm = $rr->algorithm;
    $rr->algorithm( $algorithm );

The Hash Algorithm field is represented as an unsigned decimal
integer.  The value has a maximum of 255. 

=head2 flags

    $flags = $rr->flags;
    $rr->flags( $flags );

The Flags field is represented as an unsigned decimal integer.
The value has a maximum of 255. 

=head2 iterations

    $iterations = $rr->iterations;
    $rr->iterations( $iterations );

The Iterations field is represented as an unsigned decimal
integer.  The value is between 0 and 65535, inclusive. 

=head2 salt

    $salt = $rr->salt;
    $rr->salt( $salt );

The Salt field is represented as a contiguous sequence of hexadecimal
digits. A "-" (unquoted) is used in string format to indicate that the
salt field is absent. 

=head2 saltbin

    $saltbin = $rr->saltbin;
    $rr->saltbin( $saltbin );

The Salt field as a sequence of octets. 


=head1 COPYRIGHT

Copyright (c)2007,2008 NLnet Labs.  Author Olaf M. Kolkman

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

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC5155

=cut
