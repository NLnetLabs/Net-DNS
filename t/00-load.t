# $Id$	-*-perl-*-

use strict;
use Test::More tests => 32;

use Net::DNS;

use constant DNSSEC => eval { require Net::DNS::SEC; } || 0;
use constant INET6  => eval { require IO::Socket::INET6; } || 0;
use constant LibIDN => eval { require Net::LibIDN; } || 0;


diag("\n\nThese tests were run using:\n");
diag("$^O, perl\t$]");
diag("Net::DNS\t$Net::DNS::VERSION");
diag("optional: Net::DNS::SEC\t$Net::DNS::SEC::VERSION") if DNSSEC;
diag("optional: Net::LibIDN\t\t$Net::LibIDN::VERSION") if LibIDN;
diag("optional: IO::Socket::INET6\t$IO::Socket::INET6::VERSION") if INET6;
diag("set environment variable NET_DNS_DEBUG to get all versions\n\n");


use_ok('Net::DNS');
use_ok('Net::DNS::Resolver::Recurse');

is( Net::DNS->version, $Net::DNS::VERSION, 'Net::DNS->version');


#
# Check on-demand loading using this (incomplete) list of RR packages
my @rrs = qw( A AAAA CNAME MX NS NULL PTR SOA TXT );

sub is_rr_loaded {
	my $rr = shift;
	return $INC{"Net/DNS/RR/$rr.pm"} ? 1 : 0;
}

#
# Make sure that we start with none of the RR packages loaded
foreach my $rr (@rrs) {
	ok( !is_rr_loaded($rr), "not yet loaded Net::DNS::RR::$rr" );
}

#
# Check that each RR package is loaded on demand
local $SIG{__WARN__} = sub { };					# suppress warnings

foreach my $rr (@rrs) {
	my $object = eval { new Net::DNS::RR( name => '.', type => $rr ); };
	diag($@) if $@;						# report exceptions

	ok( is_rr_loaded($rr), "loaded package Net::DNS::RR::$rr" );
}


#
# Check that Net::DNS symbol table was imported correctly
{
	no strict 'refs';
	foreach my $sym (@Net::DNS::EXPORT) {
		ok( defined &{$sym}, "$sym is imported" );
	}
}


exit;

