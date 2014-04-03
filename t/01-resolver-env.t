# $Id$  -*-perl-*-

use strict;
use Test::More tests => 13;

BEGIN {
	local $ENV{'RES_NAMESERVERS'} = '10.0.1.128 10.0.2.128';
	local $ENV{'RES_SEARCHLIST'}  = 'net-dns.org lib.net-dns.org';
	local $ENV{'LOCALDOMAIN'}     = 't.net-dns.org';
	local $ENV{'RES_OPTIONS'}     = 'retrans:3 retry:2 debug';

	use_ok('Net::DNS');
}


my $res = Net::DNS::Resolver->new;
ok( $res, "new() returned something" );

my @servers = $res->nameservers;
ok( scalar(@servers), "nameservers() works" );


is( $servers[0], '10.0.1.128', 'Nameserver set correctly' );
is( $servers[1], '10.0.2.128', 'Nameserver set correctly' );


my @search = $res->searchlist;
is( $search[0], 'net-dns.org',	   'Search set correctly' );
is( $search[1], 'lib.net-dns.org', 'Search set correctly' );

is( $res->domain,  't.net-dns.org', 'Local domain works' );
is( $res->retrans, 3,		    'Retransmit works' );
is( $res->retry,   2,		    'Retry works' );
ok( $res->debug, 'Debug works' );


{
	my $DNSSEC = eval { require Net::DNS::SEC; };

	my @warning;
	local $SIG{__WARN__} = sub { @warning = @_; };

	if ($DNSSEC) {
		my $oldsize = $res->udppacketsize();

		$res->dnssec(1);
		is( scalar(@warning), 0, 'no warning setting $res->dnssec(1)' );

		my $size = $res->udppacketsize();
		isnt( $size, $oldsize, "dnssec(1) sets udppacketsize ($size)" );

	} else {
		my $size = $res->udppacketsize();
		is( $size, 0, 'udppacketsize unspecified' );

		$res->dnssec(1);
		isnt( scalar(@warning), 0, "expected warning: [@warning]" );
	}

}

