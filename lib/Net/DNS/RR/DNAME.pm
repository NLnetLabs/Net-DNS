package Net::DNS::RR::DNAME;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::DNAME - DNS DNAME resource record

=cut


use integer;

use Net::DNS::DomainName;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;

	$self->{target} = decode Net::DNS::DomainName2535(@_);
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless $self->{target};
	$self->{target}->encode(@_);
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{target};
	$self->{target}->string;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->target(shift);
}


sub target {
	my $self = shift;

	$self->{target} = new Net::DNS::DomainName2535(shift) if scalar @_;
	$self->{target}->name if defined wantarray && $self->{target};
}


sub dname { &target; }			## historical

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name DNAME target');

=head1 DESCRIPTION

Class for DNS Non-Terminal Name Redirection (DNAME) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 target

    $target = $rr->target;
    $rr->target( $target );

Redirection target domain name which is to be substituted
for its owner as a suffix of a domain name.


=head1 COPYRIGHT

Copyright (c)2002 Andreas Gustafsson. 

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC2672

=cut
