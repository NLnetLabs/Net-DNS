package Net::DNS::RR::AAAA;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];

use base Net::DNS::RR;

=head1 NAME

Net::DNS::RR::AAAA - DNS AAAA resource record

=cut


use strict;
use integer;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	$self->{address} = unpack "\@$offset a16", $$data;
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless length $self->{address};
	pack 'a16', $self->{address};
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless length $self->{address};
	return $self->address_short;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->address(shift);
}


sub address {
	my $self = shift;

	return $self->address_long unless @_;

	my $argument = shift;
	my @parse = split /:/, "0$argument";

	if ( (@parse)[$#parse] =~ /\./ ) {			# embedded IPv4
		my @ip4 = split /\./, pop(@parse);
		my $rhs = pop(@ip4) || 0;
		my @ip6 = map { /./ ? hex($_) : (0) x ( 7 - @parse ) } @parse;
		return $self->{address} = pack 'n6 C4', @ip6, @ip4, (0) x ( 3 - @ip4 ), $rhs;
	}

	# Note: pack() masks overlarge values, mostly without warning.
	my @expand = map { /./ ? hex($_) : (0) x ( 9 - @parse ) } @parse;
	$self->{address} = pack 'n8', @expand;
}

sub address_long {
	return sprintf '%x:%x:%x:%x:%x:%x:%x:%x', unpack 'n8', shift->{address};
}

sub address_short {
	for ( sprintf ':%x:%x:%x:%x:%x:%x:%x:%x:', unpack 'n8', shift->{address} ) {
		s/(:0[:0]+:)(?!.+:0\1)/::/;			# squash longest zero sequence
		return $1 if /^(::.*):$/;			# leading ::
		return $1 if /^:(.*::)$/;			# trailing ::
		return /^:(.+):$/ ? $1 : $_;			# strip outer :s
	}
}

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name IN AAAA address');

    $rr = new Net::DNS::RR(
	name	=> 'example.com',
	type	=> 'AAAA',
	address => '2001:DB8::8:800:200C:417A'
	);

=head1 DESCRIPTION

Class for DNS IPv6 Address (AAAA) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 address

    $IPv6_address = $rr->address;

Returns the text representation of the IPv6 address.

=head2 address_long

    $IPv6_address = $rr->address_long;

Returns the text representation specified in RFC3513, 2.2(1).

=head2 address_short

    $IPv6_address = $rr->address_short;

Returns the textual form of address recommended by RFC5952.


=head1 COPYRIGHT

Copyright (c)1997-1998 Michael Fuhr. 

Portions Copyright (c)2002-2004 Chris Reinhardt.

Portions Copyright (c)2012 Dick Franks.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC3596, RFC3513, RFC5952

=cut
