# $Id: 01-resolver.t,v 1.3 2002/02/26 04:21:06 ctriv Exp $


use Test::More tests => 3;
use strict;

BEGIN { use_ok('Net::DNS'); }

my $res = Net::DNS::Resolver->new;

ok($res,                "new() returned something");
ok($res->nameservers,   "nameservers() works");

 
 
