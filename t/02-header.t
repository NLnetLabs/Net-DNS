# $Id: 02-header.t,v 1.3 2002/02/26 04:21:06 ctriv Exp $

use Test::More tests => 2;
use strict;

BEGIN { use_ok('Net::DNS'); }

my $header = Net::DNS::Header->new;

ok($header,                "new() returned something");

