# $Id$    -*-perl-*-

use Test::More tests => 31;
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




# All these tests are based on the example in RFC4291
# 20010DB80000CD3/60

my @prefixes=qw (
      2001:0DB8::CD30:0:0:0:0/60
      2001:0DB8:0000:CD30:0000:0000:0000:0000/60
      2001:0DB8::CD30:0:0:0:0/60
      2001:0DB8:0:CD30::/60
      2001:0DB8:0:CD30:123:4567:89AB:CDEF/60
);

foreach my $prefix  (@prefixes ){
    my $q5= Net::DNS::Question->new($prefix,"IN","A");
    is($q5->qname, '3.D.C.0.0.0.0.8.B.D.0.1.0.0.2.ip6.arpa','v6: prefix notation for '. $prefix);
    is($q5->qtype,  'PTR',         'v6: PTR for ' . $prefix );
    
}


my $q6= Net::DNS::Question->new($prefixes[1],"IN","NS");
is($q6->qtype,  'NS',         'v6: NS done correctly'  );

my $q7= Net::DNS::Question->new($prefixes[1],"IN","SOA");
is($q7->qtype,  'SOA',         'v6: SOA done correctly'  );



my $q8= Net::DNS::Question->new("::1.de","IN","A");
is ($q8->qname, '::1.de',"No expantion under TLD ");

my $q9= Net::DNS::Question->new('0');

is ($q9->qname, "0.in-addr.arpa","Zero gets treated as IP address");

