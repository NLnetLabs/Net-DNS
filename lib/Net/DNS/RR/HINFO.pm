package Net::DNS::RR::HINFO;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::HINFO - DNS HINFO resource record

=cut


use integer;

use Net::DNS::Text;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	( $self->{cpu}, $offset ) = decode Net::DNS::Text( $data, $offset );
	( $self->{os},	$offset ) = decode Net::DNS::Text( $data, $offset );
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless defined $self->{os};
	join '', $self->{cpu}->encode, $self->{os}->encode;
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless defined $self->{os};
	join ' ', $self->{cpu}->string, $self->{os}->string;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->cpu(shift);
	$self->os(shift);
	die 'too many arguments for HINFO' if scalar @_;
}


sub cpu {
	my $self = shift;

	$self->{cpu} = new Net::DNS::Text(shift) if scalar @_;
	$self->{cpu}->value if defined wantarray && $self->{cpu};
}


sub os {
	my $self = shift;

	$self->{os} = new Net::DNS::Text(shift) if scalar @_;
	$self->{os}->value if defined wantarray && $self->{os};
}

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name HINFO cpu os');

=head1 DESCRIPTION

Class for DNS Hardware Information (HINFO) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 cpu

    $cpu = $rr->cpu;
    $rr->cpu( $cpu );

Returns the CPU type for this RR.

=head2 os

    $os = $rr->os;
    $rr->os( $os );

Returns the operating system type for this RR.


=head1 COPYRIGHT

Copyright (c)1997-1998 Michael Fuhr. 

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC1035 Section 3.3.2

=cut
