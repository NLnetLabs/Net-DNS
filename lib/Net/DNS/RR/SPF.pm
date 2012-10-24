package Net::DNS::RR::SPF;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];

use base Net::DNS::RR::TXT;

=head1 NAME

Net::DNS::RR::SPF - DNS SPF resource record

=cut


use strict;
use integer;


sub spfdata {
	join '', shift->txtdata(@_);
}

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name SPF spfdata ...');

=head1 DESCRIPTION

Class for DNS Sender Policy Framework (SPF) resource records.

SPF records inherit most of the properties of the Net::DNS::RR::TXT
class.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 spfdata

    $string = $rr->spfdata;

C<spfdata> returns the policy text as a single string, regardless
of the actual number of elements.


=head1 COPYRIGHT

Copyright (c)2005 Olaf Kolkman, NLnet Labs.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, L<Net::DNS::RR::TXT>, RFC4408

=cut
