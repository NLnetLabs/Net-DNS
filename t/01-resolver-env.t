# $Id$  -*-perl-*-

use strict;

use Test::More tests => 10;

local $ENV{'RES_NAMESERVERS'} = '10.0.3.128 10.0.4.128';
local $ENV{'RES_SEARCHLIST'}  = 'net-dns.org lib.net-dns.org';
local $ENV{'LOCALDOMAIN'}     = 't.net-dns.org';
local $ENV{'RES_OPTIONS'}     = 'retrans:3 retry:2 debug';

use Net::DNS;

my $res = Net::DNS::Resolver->new;
isa_ok( $res, 'Net::DNS::Resolver', 'new() created object' );

my @servers = $res->nameservers;
ok( scalar(@servers), "nameservers() works" );
is( $servers[0], '10.0.3.128', 'nameservers list correct' );
is( $servers[1], '10.0.4.128', 'nameservers list correct' );

my @search = $res->searchlist;
is( $search[0], 'net-dns.org',	   'searchlist correct' );
is( $search[1], 'lib.net-dns.org', 'searchlist correct' );

is( $res->domain,  't.net-dns.org', 'domain works' );
is( $res->retrans, 3,		    'retrans works' );
is( $res->retry,   2,		    'retry works' );
ok( $res->debug, 'debug() works' );


exit;

