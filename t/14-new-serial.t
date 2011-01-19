# $Id$

use Test::More tests => 4;
use strict;

BEGIN { use_ok('Net::DNS'); }

my $rr = Net::DNS::RR->new('zone.com IN SOA ns.zone.com. postmaster.zone.com. ( 1 3600 600 86400 3600)');

my $prevserial = $rr->serial;

ok($prevserial <  $rr->new_serial, 'SOA serial based on date is larger than one');
$prevserial = $rr->serial;
ok($prevserial <  $rr->new_serial, 'SOA serial keeps getting larger');
ok($prevserial == $rr->new_serial(-1), '... except when incrementing with a negative value');

