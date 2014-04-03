package Net::DNS::RR::MG;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::MG - DNS MG resource record

=cut


use integer;

use Net::DNS::DomainName;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;

	$self->{mgmname} = decode Net::DNS::DomainName1035(@_);
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	$self->{mgmname}->encode(@_);
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	$self->{mgmname}->string;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->mgmname(shift);
}


sub mgmname {
	my $self = shift;

	$self->{mgmname} = new Net::DNS::DomainName1035(shift) if scalar @_;
	$self->{mgmname}->name if defined wantarray;
}

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name MG mgmname');

=head1 DESCRIPTION

Class for DNS Mail Group (MG) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 mgmname

    $mgmname = $rr->mgmname;
    $rr->mgmname( $mgmname );

A domain name which specifies a mailbox which is a member
of the mail group specified by the owner name.


=head1 COPYRIGHT

Copyright (c)1997-2002 Michael Fuhr. 

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC1035 Section 3.3.6

=cut
