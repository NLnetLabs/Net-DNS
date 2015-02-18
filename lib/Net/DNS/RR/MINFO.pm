package Net::DNS::RR::MINFO;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::MINFO - DNS MINFO resource record

=cut


use integer;

use Net::DNS::Mailbox;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset, @opaque ) = @_;

	( $self->{rmailbx}, $offset ) = decode Net::DNS::Mailbox1035(@_);
	( $self->{emailbx}, $offset ) = decode Net::DNS::Mailbox1035( $data, $offset, @opaque );
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;
	my ( $offset, @opaque ) = @_;

	return '' unless $self->{emailbx};
	my $rdata = $self->{rmailbx}->encode(@_);
	$rdata .= $self->{emailbx}->encode( $offset + length $rdata, @opaque );
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{emailbx};
	join ' ', map $self->{$_}->string, qw(rmailbx emailbx);
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->rmailbx(shift);
	$self->emailbx(shift);
}


sub rmailbx {
	my $self = shift;

	$self->{rmailbx} = new Net::DNS::Mailbox1035(shift) if scalar @_;
	$self->{rmailbx}->address if defined wantarray && $self->{rmailbx};
}


sub emailbx {
	my $self = shift;

	$self->{emailbx} = new Net::DNS::Mailbox1035(shift) if scalar @_;
	$self->{emailbx}->address if defined wantarray && $self->{emailbx};
}

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name MINFO rmailbx emailbx');

=head1 DESCRIPTION

Class for DNS Mailbox Information (MINFO) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 rmailbx

    $rmailbx = $rr->rmailbx;
    $rr->rmailbx( $rmailbx );

A domain name  which specifies a mailbox which is
responsible for the mailing list or mailbox.  If this
domain name names the root, the owner of the MINFO RR is
responsible for itself. Note that many existing mailing
lists use a mailbox X-request to identify the maintainer
of mailing list X, e.g., Msgroup-request for Msgroup.
This field provides a more general mechanism.

=head2 emailbx

    $emailbx = $rr->emailbx;
    $rr->emailbx( $emailbx );

A domain name  which specifies a mailbox which is to
receive error messages related to the mailing list or
mailbox specified by the owner of the MINFO RR (similar
to the ERRORS-TO: field which has been proposed).
If this domain name names the root, errors should be
returned to the sender of the message.


=head1 COPYRIGHT

Copyright (c)1997-2002 Michael Fuhr. 

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC1035 Section 3.3.7

=cut
