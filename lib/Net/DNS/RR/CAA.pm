package Net::DNS::RR::CAA;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::CAA - DNS CAA resource record

=cut


use integer;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $taglen = unpack "\@$offset x C", $$data;
	my $vallen = $self->{rdlength} - $taglen - 1;
	@{$self}{qw(flags tag value)} = unpack "\@$offset C x a$taglen a$vallen", $$data;
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	my $tag = $self->tag || return '';
	pack "C2 a* a*", $self->flags, length($tag), $tag, $self->value;
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	my $tag = $self->tag || return '';
	join ' ', $self->flags, $tag, $self->value;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	foreach my $attr (qw(flags tag value)) {
		$self->$attr(shift) if scalar @_;
	}

}


sub tag {
	my $self = shift;

	$self->{tag} = shift if scalar @_;
	$self->{tag} || "";
}


sub value {
	my $self = shift;

	$self->{value} = shift if scalar @_;
	$self->{value} || "";
}


sub flags {
	my $self = shift;

	$self->{flags} = 0 + shift if scalar @_;
	return $self->{flags} || 0;
}


sub critical {
	my $bit = 0x0080;
	for ( shift->{flags} ||= 0 ) {
		return $_ & $bit unless scalar @_;
		my $set = $_ | $bit;
		$_ = (shift) ? $set : ( $set ^ $bit );
		return $_ & $bit;
	}
}

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name IN CAA flags tag value');

=head1 DESCRIPTION

Class for Certification Authority Authorization (CAA) DNS resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 tag

    $tag = $rr->tag;
    $rr->tag( $tag );

The property identifier, a sequence of ASCII characters.

Tag values may contain ASCII characters a-z, A-Z, and 0-9.
Tag values should not contain any other characters.
Matching of tag values is not case sensitive.

=head2 value

    $value = $rr->value;
    $rr->value( $value );

A sequence of octets representing the property value.
Property values are encoded as binary values and may employ
sub-formats.

=head2 flags

    $flags = $rr->flags;
    $rr->flags( $flags );

Unsigned 8-bit number representing Boolean flags.

=head2 critical

    $rr->critical(0);
    $rr->critical(1);

    if ( $rr->critical ) {
	...
    }

Issuer critical flag.


=head1 COPYRIGHT

Copyright (c)2013 Dick Franks

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC6844

=cut
