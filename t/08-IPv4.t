# $Id$ -*-perl-*-

use strict;
use Test::More;
use t::NonFatal;

use Net::DNS;

my $debug = 0;

my @hints = qw(
		198.41.0.4
		192.228.79.201
		192.33.4.12
		199.7.91.13
		192.203.230.10
		192.5.5.241
		192.112.36.4
		198.97.190.53
		192.36.148.17
		192.58.128.30
		193.0.14.129
		199.7.83.42
		202.12.27.33
		);


exit( plan skip_all => 'Online tests disabled.' ) if -e 't/online.disabled';
exit( plan skip_all => 'Online tests disabled.' ) unless -e 't/online.enabled';


eval {
	my $resolver = new Net::DNS::Resolver();
	exit plan skip_all => 'No nameservers' unless $resolver->nameservers;

	my $reply = $resolver->send(qw(. NS IN)) || die;

	my @ns = grep $_->type eq 'NS', $reply->answer, $reply->authority;
	exit plan skip_all => 'Local nameserver broken' unless scalar @ns;

	1;
} || exit( plan skip_all => 'Non-responding local nameserver' );


eval {
	my $resolver = new Net::DNS::Resolver( nameservers => [@hints] );
	exit plan skip_all => 'No IPv4 transport' unless $resolver->nameservers;

	my $reply = $resolver->send(qw(. NS IN)) || die;

	my @ns = grep $_->type eq 'NS', $reply->answer, $reply->authority;
	exit plan skip_all => 'Unexpected response from root server' unless scalar @ns;

	1;
} || exit( plan skip_all => 'Unable to reach global root nameservers' );


my $IP = eval {
	my $resolver = Net::DNS::Resolver->new();
	my $nsreply  = $resolver->send(qw(net-dns.org NS IN)) || die;
	my @nsdname  = map $_->nsdname, grep $_->type eq 'NS', $nsreply->answer;

	# assume any IPv4 net-dns.org nameserver will do
	$resolver->force_v4(1);
	$resolver->nameservers(@nsdname);

	my @ip = $resolver->nameservers();
	scalar(@ip) ? [@ip] : undef;
} || exit( plan skip_all => 'Unable to reach target nameserver' );

diag join( "\n\t", 'will use nameservers', @$IP ) if $debug;


plan tests => 58;

NonFatalBegin();


{
	my $resolver = Net::DNS::Resolver->new( nameservers => $IP );

	my $udp = $resolver->send(qw(net-dns.org SOA IN));
	ok( $udp, '$resolver->send(...)	UDP' );

	$resolver->usevc(1);

	my $tcp = $resolver->send(qw(net-dns.org SOA IN));
	ok( $tcp, '$resolver->send(...)	TCP' );
}


{
	my $resolver = Net::DNS::Resolver->new( nameservers => $IP );
	$resolver->force_v6(1);

	my @ns = $resolver->nameservers;
	is( $resolver->errorstring, 'IPv4 transport disabled', 'force_v6(1) gives error' );

	my $udp = $resolver->send(qw(net-dns.org SOA IN));
	ok( !$udp, 'fail $resolver->send()	UDP' );

	$resolver->usevc(1);

	my $tcp = $resolver->send(qw(net-dns.org SOA IN));
	ok( !$tcp, 'fail $resolver->send()	TCP' );
}


{
	my $resolver = Net::DNS::Resolver->new( nameservers => $IP );
	$resolver->dnssec(1);
	$resolver->udppacketsize(513);

	my $udp = $resolver->send(qw(net-dns.org SOA IN));
	ok( !$udp->header->tc, '$resolver->send(...)	truncated UDP reply, TCP retry' );

	$resolver->igntc(1);

	my $trunc = $resolver->send(qw(net-dns.org SOA IN));
	ok( $trunc->header->tc, '$resolver->send(...)	ignore UDP truncation' );
}


{
	my $resolver = Net::DNS::Resolver->new( nameservers => $IP );

	my $udp = $resolver->bgsend(qw(net-dns.org SOA IN));
	ok( $udp, '$resolver->bgsend(...)	UDP' );
	until ( $resolver->bgisready($udp) ) {
		sleep 1;
	}
	ok( $resolver->bgread($udp), '$resolver->bgread()' );

	$resolver->usevc(1);

	my $tcp = $resolver->bgsend(qw(net-dns.org SOA IN));
	ok( $tcp, '$resolver->bgsend(...)	TCP' );
	until ( $resolver->bgisready($tcp) ) {
		sleep 1;
	}
	ok( $resolver->bgread($tcp), '$resolver->bgread()' );

	ok( $resolver->bgisready(undef),	     '$resolver->bgisready(undef)' );
	ok( !$resolver->bgisready( ref($udp)->new ), '$resolver->bgisready(Socket->new)' );
	ok( !$resolver->bgread(undef),		     '$resolver->bgread(undef)' );
	ok( !$resolver->bgread( ref($udp)->new ),    '$resolver->read(Socket->new)' );

	my $sock     = $resolver->bgsend(qw(net-dns.org SOA IN));
	my $appendix = ${*$sock}{net_dns_bg};
	$appendix->[1]++;
	ok( !$resolver->bgread($sock), '$resolver->bgread() id mismatch' );
}


{
	my $resolver = Net::DNS::Resolver->new( nameservers => $IP );
	$resolver->persistent_udp(1);

	my $handle = $resolver->bgsend(qw(net-dns.org SOA IN));
	ok( $handle,			'$resolver->bgsend(...)	persistent UDP' );
	ok( $resolver->bgread($handle), '$resolver->bgread()' );
	my $test = $resolver->bgsend(qw(net-dns.org SOA IN));
	ok( $test, '$resolver->bgsend(...)	persistent UDP' );
	is( $test, $handle, 'same UDP socket object used' );
}


{
	my $resolver = Net::DNS::Resolver->new( nameservers => $IP );
	$resolver->persistent_tcp(1);
	$resolver->usevc(1);

	my $handle = $resolver->bgsend(qw(net-dns.org SOA IN));
	ok( $handle,			'$resolver->bgsend(...)	persistent TCP' );
	ok( $resolver->bgread($handle), '$resolver->bgread()' );
	my $test = $resolver->bgsend(qw(net-dns.org SOA IN));
	ok( $test, '$resolver->bgsend(...)	persistent TCP' );
	is( $test, $handle, 'same TCP socket object used' );
	close($handle);
	ok( $resolver->bgsend(qw(net-dns.org SOA IN)), 'connection recovered after close' );
}


{
	my $resolver = Net::DNS::Resolver->new( nameservers => $IP );
	$resolver->srcaddr('0.0.0.0');
	$resolver->srcport(2345);

	my $udp = $resolver->bgsend(qw(net-dns.org SOA IN));
	ok( $udp, '$resolver->bgsend(...)	specify UDP local address & port' );

	$resolver->usevc(1);

	my $tcp = $resolver->bgsend(qw(net-dns.org SOA IN));
	ok( $tcp, '$resolver->bgsend(...)	specify TCP local address & port' );
}


{
	my $resolver = Net::DNS::Resolver->new( nameservers => $IP );
	$resolver->srcport(53);

	my $udp = $resolver->send(qw(net-dns.org SOA IN));
	ok( !$udp, '$resolver->send(...)	specify bad UDP source port' );

	$resolver->usevc(1);

	my $tcp = $resolver->send(qw(net-dns.org SOA IN));
	ok( !$tcp, '$resolver->send(...)	specify bad TCP source port' );
}


{
	my $resolver = Net::DNS::Resolver->new( nameservers => $IP );
	$resolver->srcport(53);

	my $udp = $resolver->bgsend(qw(net-dns.org SOA IN));
	ok( !$udp, '$resolver->bgsend(...)	specify bad UDP source port' );

	$resolver->usevc(1);

	my $tcp = $resolver->bgsend(qw(net-dns.org SOA IN));
	ok( !$tcp, '$resolver->bgsend(...)	specify bad TCP source port' );
}


{
	my $resolver = Net::DNS::Resolver->new();
	$resolver->retrans(0);
	$resolver->retry(0);

	my @query = ( undef, qw(SOA IN) );
	ok( $resolver->query(@query),  '$resolver->query( undef, ... ) defaults to "." ' );
	ok( $resolver->search(@query), '$resolver->search( undef, ... ) defaults to "." ' );

	$resolver->defnames(0);
	$resolver->dnsrch(0);
	ok( $resolver->search(@query), '$resolver->search() without dnsrch & defnames' );
}


{
	my $resolver = Net::DNS::Resolver->new();
	$resolver->searchlist('net');

	my @query = (qw(us SOA IN));
	ok( $resolver->query(@query),  '$resolver->query( name, ... )' );
	ok( $resolver->search(@query), '$resolver->search( name, ... )' );

	$resolver->defnames(0);
	$resolver->dnsrch(0);
	ok( $resolver->query(@query),  '$resolver->query() without defnames' );
	ok( $resolver->search(@query), '$resolver->search() without dnsrch' );
}


{
	my $resolver = Net::DNS::Resolver->new( nameservers => '192.0.2.1' );
	$resolver->tcp_timeout(1);

	my @query = (qw(. SOA IN));
	my $query = new Net::DNS::Packet(@query);
	$query->edns->option( 1, pack 'x500' );			# pad to force TCP
	ok( !$resolver->send($query),	'$resolver->send() failure' );
	ok( !$resolver->bgsend($query), '$resolver->bgsend() failure' );

	$resolver->usevc(1);
	ok( !$resolver->query(@query),	'$resolver->query() failure' );
	ok( !$resolver->search(@query), '$resolver->search() failure' );
}


{
	my $resolver = Net::DNS::Resolver->new( nameservers => $IP );
	my @mx = mx( $resolver, 'mx2.t.net-dns.org' );

	is( scalar(@mx), 2, 'mx() works with specified resolver' );

	# some people seem to use mx() in scalar context
	is( scalar mx( $resolver, 'mx2.t.net-dns.org' ), 2, 'mx() works in scalar context' );

	is( scalar mx('mx2.t.net-dns.org'), 2, 'mx() works with default resolver' );

	is( scalar mx('bogus.t.net-dns.org'), 0, "mx() works for bogus name" );
}


{
	my $resolver = Net::DNS::Resolver->new( nameservers => $IP );
	$resolver->domain('net-dns.org');
	$resolver->tcp_timeout(10);

	my @zone = eval { $resolver->axfr() };
	ok( scalar(@zone), '$resolver->axfr() works in list context' );

	my $iter = eval { $resolver->axfr() };
	is( ref($iter), 'CODE', '$resolver->axfr() returns iterator CODE ref' );
	my $i;
	while ( $iter->() ) { $i++ }
	ok( $i, '$resolver->axfr() works using iterator' );

	ok( !$iter->(), '$iter->() returns undef after last RR' );

	my $axfr_start = eval { $resolver->axfr_start() };
	ok( $axfr_start, '$resolver->axfr_start()	(historical)' );
	my $n;
	while ( $resolver->axfr_next() ) { $n++ }
	ok( $n, '$resolver->axfr_next() works' );

	ok( !$resolver->axfr_next(), '$resolver->axfr_next() returns undef after last RR' );

	$resolver->srcport(53);
	my @bad = eval { $resolver->axfr() };
	ok( !scalar(@bad), '$resolver->axfr() bad source port' );
}


{
	my $resolver = Net::DNS::Resolver->new( nameservers => $IP );
	$resolver->domain('net-dns.org');
	$resolver->tcp_timeout(10);

	eval { $resolver->tsig( 'MD5.example', 'BadMD5KeyBadkeyBadKeyBadKey=' ) };
	my @bad = eval { $resolver->axfr() };
	ok( !scalar(@bad), '$resolver->axfr() unverifiable' );
}


{
	my $resolver = Net::DNS::Resolver->new();
	$resolver->nameservers();
	ok( !scalar( $resolver->nameservers ), 'no nameservers' );
}


{
	my $resolver = Net::DNS::Resolver->new();
	$resolver->nameserver('cname.t.net-dns.org');
	ok( scalar( $resolver->nameservers ), 'resolve nameserver cname' );
}


{
	my $resolver = Net::DNS::Resolver->new();
	my @warnings;
	local $SIG{__WARN__} = sub { push( @warnings, "@_" ); };
	my $ns = 'bogus.example.com.';
	my @ip = $resolver->nameserver($ns);

	my ($warning) = @warnings;
	chomp $warning;
	ok( $warning, "unresolved nameserver warning\t[$warning]" )
			|| diag "\tnon-existent '$ns' resolved: @ip";
}


NonFatalEnd();

exit;

__END__

