package Net::DNS::RR::NAPTR;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1]; # Unchanged since 1037

use base Net::DNS::RR;

=head1 NAME

Net::DNS::RR::NAPTR - DNS NAPTR resource record

=cut


use strict;
use integer;

use Net::DNS::DomainName;
use Net::DNS::Text;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset, @opaque ) = @_;

	@{$self}{qw(order preference)} = unpack "\@$offset n2", $$data;
	( $self->{flags},   $offset ) = decode Net::DNS::Text( $data, $offset + 4 );
	( $self->{service}, $offset ) = decode Net::DNS::Text( $data, $offset );
	( $self->{regexp},  $offset ) = decode Net::DNS::Text( $data, $offset );
	$self->{replacement} = decode Net::DNS::DomainName2535($data,$offset,@opaque );
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;
	my ( $offset, @opaque ) = @_;

	return '' unless $self->{replacement};
	my $rdata .= pack 'n2', @{$self}{qw(order preference)};
	$rdata	  .= $self->{flags}->encode;
	$rdata	  .= $self->{service}->encode;
	$rdata	  .= $self->{regexp}->encode;
	$rdata	  .= $self->{replacement}->encode( $offset + length($rdata), @opaque );
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{replacement};
	my @number = @{$self}{qw(order preference)};
	my @string = map { $_->string } @{$self}{qw(flags service regexp replacement)};

	join ' ', @number, @string;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	map { $self->$_(shift) } qw(order preference flags service regexp replacement);
}


sub order {
	my $self = shift;

	$self->{order} = shift if @_;
	return 0 + ( $self->{order} || 0 );
}

sub preference {
	my $self = shift;

	$self->{preference} = shift if @_;
	return 0 + ( $self->{preference} || 0 );
}

sub flags {
	my $self = shift;

	$self->{flags} = new Net::DNS::Text(shift) if @_;
	$self->{flags}->value if defined wantarray;
}

sub service {
	my $self = shift;

	$self->{service} = new Net::DNS::Text(shift) if @_;
	$self->{service}->value if defined wantarray;
}

sub regexp {
	my $self = shift;

	$self->{regexp} = new Net::DNS::Text(shift) if @_;
	$self->{regexp}->value if defined wantarray;
}

sub replacement {
	my $self = shift;

	$self->{replacement} = new Net::DNS::DomainName2535(shift) if @_;
	$self->{replacement}->name if defined wantarray;
}

__PACKAGE__->set_rrsort_func(
	'order',
	sub {
		my ( $a, $b ) = ( $Net::DNS::a, $Net::DNS::b );
		$a->{order} <=> $b->{order}
				|| $a->{preference} <=> $b->{preference};
	} );

__PACKAGE__->set_rrsort_func(
	'preference',
	sub {
		my ( $a, $b ) = ( $Net::DNS::a, $Net::DNS::b );
		$a->{preference} <=> $b->{preference}
				|| $a->{order} <=> $b->{order};
	} );

__PACKAGE__->set_rrsort_func(
	'default_sort',
	__PACKAGE__->get_rrsort_func('order')

	);

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name NAPTR order preference flags service regexp replacement');

=head1 DESCRIPTION

DNS Naming Authority Pointer (NAPTR) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 order

    $order = $rr->order;

A 16-bit unsigned integer specifying the order in which the NAPTR
records must be processed to ensure the correct ordering of rules.
Low numbers are processed before high numbers.

=head2 preference

    $preference = $rr->preference;

A 16-bit unsigned integer that specifies the order in which NAPTR
records with equal "order" values should be processed, low numbers
being processed before high numbers.

=head2 flags

    $flags = $rr->flags;

A string containing flags to control aspects of the rewriting and
interpretation of the fields in the record.  Flags are single
characters from the set [A-Z0-9].

=head2 service

    $service = $rr->service;

Specifies the service(s) available down this rewrite path. It may
also specify the protocol used to communicate with the service.

=head2 regexp

    $regexp = $rr->regexp;

A string containing a substitution expression that is applied to
the original string held by the client in order to construct the
next domain name to lookup.

=head2 replacement

    $replacement = $rr->replacement;

The next NAME to query for NAPTR, SRV, or address records
depending on the value of the flags field.


=head1 COPYRIGHT

Copyright (c)2005 Olaf Kolkman, NLnet Labs.

Based on code contributed by Ryan Moats.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC2915, RFC2168, RFC3403

=cut
