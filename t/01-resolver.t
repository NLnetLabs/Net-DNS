# $Id$	-*-perl-*-

use strict;
use Test::More tests => 48;
use t::NonFatal;

use Net::DNS;

my $res = Net::DNS::Resolver->new();

for (@Net::DNS::Resolver::ISA) {
	diag "$_\t($^O)" unless /[:]UNIX$/;
}

isa_ok( $res, 'Net::DNS::Resolver', 'new() created object' );


ok( scalar $res->nameservers(qw(::1 127.0.0.1)), 'nameservers() works' );


my $searchlist = [qw(t.net-dns.org t2.net-dns.org)];

is_deeply( [$res->searchlist(@$searchlist)], $searchlist, 'setting searchlist returns correctly.' );
is_deeply( [$res->searchlist], $searchlist, 'setting searchlist sticks.' );


my %good_input = (
	port	       => 54,
	srcaddr	       => '10.1.0.1',
	srcport	       => 53,
	domain	       => 'net-dns.org',
	retrans	       => 6,
	retry	       => 5,
	usevc	       => 1,
	stayopen       => 1,
	igntc	       => 1,
	recurse	       => 0,
	defnames       => 0,
	dnsrch	       => 0,
	debug	       => 1,
	tcp_timeout    => 60,
	udp_timeout    => 60,
	persistent_tcp => 1,
	dnssec	       => 0,
	force_v4       => 1,
	prefer_v6      => 1,
	cdflag	       => 0,
	adflag	       => 1,
	);


while ( my ( $param, $value ) = each %good_input ) {

	is_deeply( $res->$param($value), $value, "setting $param returns correctly" );
	is_deeply( $res->$param(),	 $value, "setting $param sticks" );
}


SKIP: {
	# Test first, if we want online tests at all.
	skip 'Online tests disabled.', 2 unless -e 't/online.enabled';
	skip 'Online tests disabled.', 2 if -e 't/online.disabled';

	# Some people try to run these on private address space - test for this case and skip.
	use IO::Socket::INET;

	my $sock = IO::Socket::INET->new(
		PeerAddr => '193.0.14.129',			# k.root-servers.net.
		PeerPort => '53',
		Proto	 => 'udp'
		);


	my $ip = $sock ? inet_ntoa( $sock->sockaddr ) : undef;

	skip "Tests may not succeed from private IP: $ip", 2
			if $ip && $ip =~ /^(10|172\.(1[6-9]|2.|30|31)|192.168)\./;

	NonFatalBegin();

	my $res = Net::DNS::Resolver->new( udp_timeout => 3, tcp_timeout => 3 );

	my %hosts = (
		'a.t.net-dns.org'	=> '10.0.1.128',
		'cname.t.net-dns.org'	=> '10.0.1.128',
		);

	while ( my ( $host, $ip ) = each %hosts ) {
		$res->nameservers($host);			# multi-homed / dual-stack ?
		my %result = map { ( $_ => $_ ) } $res->nameservers();
		ok( $result{$ip}, "nameservers('$host') returns expected IP" )
				or diag( $res->errorstring . $res->print );
	}

	NonFatalEnd();
}


exit;

