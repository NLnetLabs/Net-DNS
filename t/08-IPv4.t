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
	my @ip = $resolver->nameservers(@nsdname);
	scalar(@ip) ? [@ip] : undef;
} || exit( plan skip_all => 'Unable to reach target nameserver' );

diag join( "\n\t", 'will use nameservers', @$IP ) if $debug;


plan tests => 31;

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
}


{
	my $resolver = Net::DNS::Resolver->new( nameservers => $IP );
	$resolver->persistent_udp(1);

	my $handle = $resolver->bgsend(qw(net-dns.org SOA IN));
	ok( $handle,			'$resolver->bgsend(...)	persistent UDP' );
	ok( $resolver->bgread($handle), '$resolver->bgread()' );
	my $test = $resolver->bgsend(qw(net-dns.org SOA IN));
	ok( $test, '$resolver->bgsend(...)	persistent UDP' );
	is( $test->[0], $handle->[0], 'same UDP socket object used' );
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
	is( $test->[0], $handle->[0], 'same TCP socket object used' );
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
	$resolver->tcp_timeout(10);
	eval { $resolver->tsig( 'MD5.example', 'ARDJZgtuTDzAWeSGYPAu9uJUkX0=' ) };

	my $iter = $resolver->axfr('example.com');
	is( ref($iter), 'CODE', '$resolver->axfr() returns iterator CODE ref' );
	my $error = $resolver->errorstring;
	like( $error, '/NOTAUTH/', '$resolver->errorstring() reports RCODE from server' );

	my @zone = eval { $resolver->axfr('example.com') };
	ok( $resolver->errorstring, '$resolver->axfr() works in list context' );

	ok( $resolver->axfr_start('example.com'), '$resolver->axfr_start()	(historical)' );
	is( $resolver->axfr_next(), undef, '$resolver->axfr_next()' );
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
	$resolver->nameserver('bogus.example.com');
	my ($warning) = @warnings;
	chomp $warning;
	ok( $warning, "unresolved nameserver warning\t[$warning]" );
}


NonFatalEnd();

exit;

__END__

