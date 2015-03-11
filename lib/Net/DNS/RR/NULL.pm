package Net::DNS::RR::NULL;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::NULL - DNS NULL resource record

=cut


1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name NULL \# length hexdata ...');

=head1 DESCRIPTION

Class for DNS null (NULL) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 rdlength

    $rdlength = $rr->rdlength;

Returns the length of the record data section.

=head2 rdata

    $rdata = $rr->rdata;
    $rr->rdata( $rdata );

Returns the record data section as binary data.


=head1 COPYRIGHT

Copyright (c)1997 Michael Fuhr.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC1035 Section 3.3.10

=cut
