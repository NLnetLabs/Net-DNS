# $Id: 03-question.t,v 1.3 2002/02/26 04:21:06 ctriv Exp $

use Test::More tests => 5;
use strict;

BEGIN { use_ok('Net::DNS'); }


my $domain = 'example.com';
my $type   = 'MX';
my $class  = 'IN';

my $q = Net::DNS::Question->new($domain, $type, $class);

ok($q,                 'new() returned something.');
is($q->qname, $domain, 'qname()' );
is($q->qtype, $type,   'qtype()' );
is($q->qclass, $class, 'qclass()');
