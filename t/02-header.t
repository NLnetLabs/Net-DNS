# $Id: 02-header.t,v 1.5 2002/08/21 00:07:42 ctriv Exp $

use Test::More tests => 3;
use strict;

BEGIN { use_ok('Net::DNS'); }

my $header = Net::DNS::Header->new;

ok($header,                "new() returned something");

$header->id(41);
$header->qr(1);
$header->opcode('QUERY');
$header->aa(1);
$header->tc(0);
$header->rd(1);
$header->cd(0);
$header->ra(1);
$header->rcode("NOERROR");

$header->qdcount(1);
$header->ancount(2);
$header->nscount(3);
$header->arcount(3);

my $data = $header->data;

my $header2 = Net::DNS::Header->new(\$data);

is_deeply($header, $header2, 'Headers are the same');