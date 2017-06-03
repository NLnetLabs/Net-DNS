# $Id$

use strict;
use Test::More;


BEGIN {
	eval { system('cp t/.resolv.conf .') };
}

END { unlink('.resolv.conf') }


plan skip_all => "user .resolv.conf parsing not supported on $^O"
		if $^O =~ /^(cygwin|MSWin32)$/;

plan skip_all => 'Could not read .resolv.conf configuration file'
		unless -r '.resolv.conf' && -o _;

plan tests => 16;


use Net::DNS;

local $ENV{'RES_NAMESERVERS'};
local $ENV{'RES_SEARCHLIST'};
local $ENV{'LOCALDOMAIN'};
local $ENV{'RES_OPTIONS'};

my $class = 'Net::DNS::Resolver';

{
	$class->domain('domain.default');
	my $resolver = $class->new();
	ok( $resolver->isa($class), 'new() using ./.resolv.conf' );
	my @servers = $resolver->nameservers;
	ok( scalar(@servers), 'nameservers list populated' );
	is( $servers[0], '10.0.1.128', 'nameservers list correct' );
	is( $servers[1], '10.0.2.128', 'nameservers list correct' );

	my @search = $resolver->searchlist;
	ok( scalar(@search), 'searchlist populated' );
	is( $search[0], 'net-dns.org',	   'searchlist correct' );
	is( $search[1], 'lib.net-dns.org', 'searchlist correct' );

	is( $resolver->domain, 'net-dns.org', 'domain correct' );

	is( $class->domain, $resolver->domain, 'initial config sets defaults' );
}


{
	my $filename = 't/custom.txt';
	my $resolver = $class->new( config_file => $filename );
	ok( $resolver->isa($class), "new( config_file => $filename )" );

	my @servers = $resolver->nameservers;
	ok( scalar(@servers), 'nameservers list populated' );

	my $domain = 'alt.net-dns.org';
	my @search = $resolver->searchlist;
	is( scalar(@search), 1,	      'single domain searchlist' );
	is( shift(@search),  $domain, 'searchlist correct' );

	is( $resolver->domain, $domain, 'domain correct' );

	isnt( $class->domain, $resolver->domain, 'default config unchanged' );
}


{								# file presumed not to exist
	eval { new $class( config_file => 'nonexist.txt' ); };
	my $exception = $1 if $@ =~ /^(.+)\n/;
	ok( $exception ||= '', "new( config_file => ?\t[$exception]" );
}


exit;

