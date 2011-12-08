# $Id$

use Test::More tests => 19;
use strict;

BEGIN { use_ok('Net::DNS'); }

my $packet = new Net::DNS::Packet(qw(. NS IN));
my $header = $packet->header;

ok($header, 'packet->header returned something');

$header->id(41);
$header->qr(1);
$header->opcode('QUERY');
$header->aa(1);
$header->tc(0);
$header->rd(1);
$header->cd(0);
$header->ra(1);
$header->rcode("NOERROR");

is($header->id,     41,        'id() works');
is($header->qr,     1,         'qr() works');
is($header->opcode, 'QUERY',   'opcode() works');
is($header->aa,     1,         'aa() works');
is($header->tc,     0,         'tc() works');
is($header->rd,     1,         'rd() works');
is($header->cd,     0,         'cd() works');
is($header->ra,     1,         'ra() works');
is($header->rcode,  'NOERROR', 'rcode() works');


my $data = $packet->data;

my $packet2 = new Net::DNS::Packet(\$data);
my $header2 = $packet2->header;

is_deeply($header, $header2, 'encode/decode transparent');


#
#  Is $header->string remotely sane?
#
like($header->string, '/opcode = QUERY/', 'string() has opcode correct');
like($header->string, '/qdcount = 1/',    'string() has qdcount correct');
like($header->string, '/ancount = 0/',    'string() has ancount correct');


#
# Check that the aliases work properly.
#
$header->zocount(0);
$header->prcount(1);
$header->upcount(2);
$header->adcount(3);

is($header->qdcount, 0, 'zocount works');
is($header->ancount, 1, 'prcount works');
is($header->nscount, 2, 'upcount works');
is($header->arcount, 3, 'adcount works');

