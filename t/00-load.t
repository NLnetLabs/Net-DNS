# $Id$	-*-perl-*-

use strict;
use diagnostics;
use Test::More;


BEGIN {
	use_ok('Net::DNS');
	use_ok('Net::DNS::Resolver::Recurse');
	use_ok('Net::DNS::Nameserver');
	use_ok('Net::DNS::Resolver::Cygwin');

	# can't test windows, has registry stuff
}


diag("\nThese tests were run using:\n");
diag("Net::DNS::VERSION:\t$Net::DNS::VERSION");
diag("Net::DNS::SEC seems to be available") if $Net::DNS::DNSSEC;
diag("set environment variable NET_DNS_DEBUG to get all versions");


sub is_rr_loaded {
	my $rr = shift;

	return $INC{"Net/DNS/RR/$rr.pm"} ? 1 : 0;
}


#
# Check on-demand loading using this list of RR packages
my @rrs = qw( CNAME HINFO MB MG MINFO MR MX NULL NS PTR SOA TXT A
		AFSDB DNAME KX NAPTR PX RP RT SRV
		AAAA APL CERT DHCID EID HIP IPSECKEY ISDN LOC
		NIMLOC OPT SPF SSHFP TKEY TSIG X25 );


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


##############
done_testing()
##############
