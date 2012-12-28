package Net::DNS::RR::ISDN;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1]; # Unchanged since 1037

use base Net::DNS::RR;

=head1 NAME

Net::DNS::RR::ISDN - DNS ISDN resource record

=cut


use strict;
use integer;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $asize = unpack "\@$offset C", $$data;
	$self->{address} = unpack "\@$offset x a$asize", $$data;
	$offset += 1 + $asize;
	my $ssize = unpack "\@$offset C", $$data;
	$self->{sa} = unpack "\@$offset x a$ssize", $$data;
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless $self->{address};
	pack 'C a* C a*', map { ( length $_, $_ ) } @{$self}{qw(address sa)};
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{address};
	join ' ', @{$self}{qw(address sa)};
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->address(shift);
	$self->sa(shift);
}


sub address {
	my $self = shift;

	$self->{address} = shift if @_;
	$self->{address} || "";
}

sub sa {
	my $self = shift;

	$self->{sa} = shift if @_;
	$self->{sa} || "";
}

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name ISDN address sa');

=head1 DESCRIPTION

Class for DNS ISDN resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 address

    $address = $rr->address;

The ISDN-address is a string of characters, normally decimal
digits, beginning with the E.163 country code and ending with
the DDI if any.

=head2 sa

    $sa = $rr->sa;

The optional subaddress (SA) is a string of hexadecimal digits.


=head1 COPYRIGHT

Copyright (c)1997 Michael Fuhr. 

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC1183 Section 3.2

=cut
