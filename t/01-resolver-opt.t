# $Id$    -*-perl-*-


use Test::More tests => 52;
use strict;
use File::Spec;

use Net::DNS;


# .txt because this test will run under windows, unlike the other file
# configuration tests.
my $test_file = File::Spec->catfile( 't', 'custom.txt' );

my $res = Net::DNS::Resolver->new( config_file => $test_file );
isa_ok( $res, 'Net::DNS::Resolver', 'new() created object' );


my @servers = $res->nameservers;
ok( scalar(@servers), 'nameservers() works' );

is( $servers[0], '10.0.1.42', 'nameserver list correct' );
is( $servers[1], '10.0.2.42', 'nameserver list correct' );


my @search = $res->searchlist;
is( $search[0], 'alt.net-dns.org', 'searchlist correct' );
is( $search[1], 'ext.net-dns.org', 'searchlist correct' );

is( $res->domain, 't2.net-dns.org', 'domain works' );

my $bad = eval { Net::DNS::Resolver->new( config_file => 'nosuch.txt' ); };
ok( $@,	   'error thrown trying to open non-existent file' );
ok( !$bad, 'Net::DNS::Resolver->new returned undef' );


#
# Check that we can set things in new()
#
undef $res;

my %test_config = (
	# NOTE: test breaks encapsulation, which limits what you can test
	#
	#nameservers	=> ['10.0.0.1', '10.0.0.2'],
	port		=> 54,
	srcaddr		=> '10.1.0.1',
	srcport 	=> 53,
	domain		=> 'net-dns.org',
	searchlist	=> ['net-dns.org', 't.net-dns.org'],
	retrans		=> 6,
	retry		=> 5,
	usevc		=> 1,
	stayopen	=> 1,
	igntc		=> 1,
	recurse		=> 0,
	defnames	=> 0,
	dnsrch		=> 0,
	debug		=> 1,
	tcp_timeout	=> 60,
	udp_timeout	=> 60,
	persistent_tcp	=> 1,
	dnssec		=> 0,
	cdflag		=> 0,
	adflag		=> 1,
);

$res = Net::DNS::Resolver->new(%test_config);


foreach my $item (keys %test_config) {
	is_deeply($res->{$item}, $test_config{$item}, "$item is correct");
}	


#
# Check that new() is vetting things properly.
#

foreach my $test (qw(nameservers searchlist)) {
	foreach my $input ({}, 'string', 1, \1, undef) {
		undef $res;
		eval { $res = Net::DNS::Resolver->new($test => $input); };
		ok($@,    'Invalid input caught');
		ok(!$res, 'No resolver returned');
	}
}




undef $res;

my %bad_input = (
	errorstring    => 'set',
	answerfrom     => 'set',
	answersize     => 'set',
);	

$res = Net::DNS::Resolver->new(%bad_input);

foreach my $key (keys %bad_input) {
	isnt($res->{$key}, 'set', "$key is not set");
}


exit;

