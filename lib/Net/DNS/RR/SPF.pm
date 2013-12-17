package Net::DNS::RR::SPF;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR::TXT);

=head1 NAME

Net::DNS::RR::SPF - DNS SPF resource record

=cut

use integer;


sub spfdata {
	return shift->char_str_list(@_) if wantarray;
	join '', shift->char_str_list(@_);
}

sub txtdata { &spfdata; }

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name SPF spfdata ...');

    $rr = new Net::DNS::RR( name    => 'name',
			    type    => 'SPF',
			    spfdata => 'single text string'
			    );

    $rr = new Net::DNS::RR( name    => 'name',
			    type    => 'SPF',
			    spfdata => [ 'multiple', 'strings', ... ]
			    );

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
    @list   = $rr->spfdata;

    $rr->spfdata( @list );

When invoked in scalar context, spfdata() returns the policy text as
a single string, with text elements concatenated without intervening
spaces.

In a list context, spfdata() returns a list of the text elements.


=head1 COPYRIGHT

Copyright (c)2005 Olaf Kolkman, NLnet Labs.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, L<Net::DNS::RR::TXT>, RFC4408

=cut
