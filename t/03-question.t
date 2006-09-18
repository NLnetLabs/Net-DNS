# $Id$

use Test::More tests => 17;
use strict;

BEGIN { use_ok('Net::DNS'); }


my $domain = 'example.com';
my $type   = 'MX';
my $class  = 'IN';

my $q = Net::DNS::Question->new($domain, $type, $class);

ok($q,                 'new() returned something.');

is($q->qname,  $domain, 'qname()'  );
is($q->qtype,  $type,   'qtype()'  );
is($q->qclass, $class,  'qclass()' );

#
# Check the aliases
#
is($q->zname,  $domain, 'zname()'  );
is($q->ztype,  $type,   'ztype()'  );
is($q->zclass, $class,  'zclass()' );

#
# Check that we can change stuff
#
$q->qname('example.net');
$q->qtype('A');
$q->qclass('CH');

is($q->qname,  'example.net', 'qname()'  );
is($q->qtype,  'A',           'qtype()'  );
is($q->qclass, 'CH',          'qclass()' );




my $q2= Net::DNS::Question->new("::1","IN","A");
is ($q2->qname, '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa','v6: qname()');
is($q2->qtype,  'PTR',         'v6: qtype()'  );
is($q2->qclass, 'IN',          'v6: qclass()' );


my $q3= Net::DNS::Question->new("192.168.1.16","IN","A");
is($q3->qname, '16.1.168.192.in-addr.arpa','v4: qname()');
is($q3->qtype,  'PTR',         'v4: qtype()' );
is($q3->qclass, 'IN',          'v4: qclass()' );



use Data::Dumper;

my $q4= Net::DNS::Question->new("8a");
print Dumper $q4;
