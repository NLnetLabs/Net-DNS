# $Id$


use strict;
use Test::More;

chdir 't/' || die "Couldn't chdir to t/\n";			# t/.resolv.conf
unshift( @INC, '../blib/lib', '../blib/arch' );

use Net::DNS;

my $res = Net::DNS::Resolver->new;

plan skip_all => 'File parsing only supported on Unix'
		unless $res->isa('Net::DNS::Resolver::UNIX');

plan skip_all => 'Could not read configuration file'
		unless -r '.resolv.conf' && -o _;

plan tests => 7;


isa_ok( $res, 'Net::DNS::Resolver', 'new() created object' );

my @servers = $res->nameservers;
ok( scalar(@servers), "nameservers() works" );
is( $servers[0], '10.0.1.128', 'nameservers list correct' );
is( $servers[1], '10.0.2.128', 'nameservers list correct' );

my @search = $res->searchlist;
is( $search[0], 'net-dns.org',	   'searchlist correct' );
is( $search[1], 'lib.net-dns.org', 'searchlist correct' );

is( $res->domain, 't.net-dns.org', 'domain works' );


exit;

