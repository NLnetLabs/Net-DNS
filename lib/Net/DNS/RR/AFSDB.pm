package Net::DNS::RR::AFSDB;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::AFSDB - DNS AFSDB resource record

=cut


use integer;

use Net::DNS::DomainName;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset, @opaque ) = @_;

	$self->{subtype} = unpack "\@$offset n", $$data;
	$self->{hostname} = decode Net::DNS::DomainName2535( $data, $offset + 2, @opaque );
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;
	my ( $offset, @opaque ) = @_;

	return '' unless $self->{hostname};
	my $rdata = pack 'n', $self->subtype;
	$rdata .= $self->{hostname}->encode( $offset + length($rdata), @opaque );
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{hostname};
	join ' ', $self->subtype, $self->{hostname}->string;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->subtype(shift);
	$self->hostname(shift);
}


sub subtype {
	my $self = shift;

	$self->{subtype} = 0 + shift if scalar @_;
	return $self->{subtype} || 0;
}


sub hostname {
	my $self = shift;

	$self->{hostname} = new Net::DNS::DomainName2535(shift) if scalar @_;
	$self->{hostname}->name if defined wantarray;
}

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name AFSDB subtype hostname');

=head1 DESCRIPTION

Class for DNS AFS Data Base (AFSDB) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 subtype

    $subtype = $rr->subtype;
    $rr->subtype( $subtype );

A 16 bit integer which indicates the service offered by the
listed host.

=head2 hostname

    $hostname = $rr->hostname;
    $rr->hostname( $hostname );

The hostname field is a domain name of a host that has a server
for the cell named by the owner name of the RR.


=head1 COPYRIGHT

Copyright (c)1997-1998 Michael Fuhr. 

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC1183, RFC5864

=cut
