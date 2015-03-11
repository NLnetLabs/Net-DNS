package Net::DNS::RR::CNAME;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::CNAME - DNS CNAME resource record

=cut


use integer;

use Net::DNS::DomainName;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;

	$self->{cname} = decode Net::DNS::DomainName1035(@_);
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless $self->{cname};
	$self->{cname}->encode(@_);
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{cname};
	$self->{cname}->string;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->cname(shift);
}


sub cname {
	my $self = shift;

	$self->{cname} = new Net::DNS::DomainName1035(shift) if scalar @_;
	$self->{cname}->name if defined wantarray && $self->{cname};
}

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name CNAME cname');

    $rr = new Net::DNS::RR(
	name  => 'alias.example.com',
	type  => 'CNAME',
	cname => 'example.com',
	);

=head1 DESCRIPTION

Class for DNS Canonical Name (CNAME) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 cname

    $cname = $rr->cname;
    $rr->cname( $cname );

A domain name which specifies the canonical or primary name for
the owner.  The owner name is an alias.


=head1 COPYRIGHT

Copyright (c)1997 Michael Fuhr. 

Portions Copyright (c)2002-2003 Chris Reinhardt.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC1035 Section 3.3.1

=cut
