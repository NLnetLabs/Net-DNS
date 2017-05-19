# $Id$

use strict;
use Test::More;


BEGIN {
	chdir 't/' || die "Couldn't chdir to t/\n";		# t/.resolv.conf
	unshift( @INC, '../blib/lib', '../blib/arch' );
}


use Net::DNS;

my $resolver = Net::DNS::Resolver->new();


plan skip_all => "user .resolv.conf parsing not supported on $^O"
		if $^O =~ /^(cygwin|MSWin32)$/;

plan skip_all => 'Could not read .resolv.conf configuration file'
		unless -r '.resolv.conf' && -o _;

plan tests => 14;


{
	ok( $resolver->isa('Net::DNS::Resolver'), 'new() using ./.resolv.conf' );
	my @servers = $resolver->nameservers;
	ok( scalar(@servers), 'nameservers list populated' );
	is( $servers[0], '10.0.1.128', 'nameservers list correct' );
	is( $servers[1], '10.0.2.128', 'nameservers list correct' );

	my @search = $resolver->searchlist;
	ok( scalar(@search), 'searchlist populated' );
	is( $search[0], 'net-dns.org',	   'searchlist correct' );
	is( $search[1], 'lib.net-dns.org', 'searchlist correct' );

	is( $resolver->domain, 'net-dns.org', 'domain correct' );
}


{								# file presumed not to exist
	eval { new Net::DNS::Resolver( config_file => 'nonexist.txt' ); };
	my $exception = $1 if $@ =~ /^(.+)\n/;
	ok( $exception ||= '', "new( config_file => ?\t[$exception]" );
}


{
	my $filename = 'custom.txt';
	my $resolver = Net::DNS::Resolver->new( config_file => $filename );
	ok( $resolver->isa('Net::DNS::Resolver'), "new( config_file => $filename )" );

	my @servers = $resolver->nameservers;
	ok( scalar(@servers), 'nameservers list populated' );

	my $domain = 'alt.net-dns.org';
	my @search = $resolver->searchlist;
	is( scalar(@search), 1,	      'single domain searchlist' );
	is( shift(@search),  $domain, 'searchlist correct' );

	is( $resolver->domain, $domain, 'domain correct' );
}


exit;

