# $Id: 07-misc.t,v 1.1 2002/08/01 08:10:48 ctriv Exp $

use Test::More tests => 11;
use strict;

BEGIN { use_ok('Net::DNS'); }


#
# test to make sure that wildcarding works.
#
my $rr;
eval { $rr = Net::DNS::RR->new('*.t.net-dns.org 60 IN A 10.0.0.1'); };

ok($rr, 'RR got made');

is($rr->name,    '*.t.net-dns.org', 'Name is correct'   );
is($rr->ttl,      60,               'TTL is correct'    );
is($rr->class,   'IN',              'CLASS is correct'  );
is($rr->type,    'A',               'TYPE is correct'   );
is($rr->address, '10.0.0.1',        'Address is correct');


#
# Make sure that we aren't loading any RR modules that we don't need... 
#   and check other autoloading stuff...
#
ok($Net::DNS::RR::_LOADED{'Net::DNS::RR::A'},   'Net::DNS::RR::A marked as loaded.');
ok(!$Net::DNS::RR::_LOADED{'Net::DNS::RR::MX'}, 'Net::DNS::RR::MX is not marked as loaded.');

ok($INC{'Net/DNS/RR/A.pm'},                     'Net::DNS::RR::A is loaded');
ok(!$INC{'Net/DNS/RR/MX.pm'},                   'Net::DNS::RR::MX is not loaded.');

