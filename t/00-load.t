# $Id$	-*-perl-*-

use strict;
use Test::More tests => 30;


my @module = qw(
	Net::DNS
	Net::DNS::SEC
	Data::Dumper
	Digest::BubbleBabble
	Digest::GOST
	Digest::HMAC
	Digest::MD5
	Digest::SHA
	File::Spec
	FileHandle
	IO::File
	IO::Select
	IO::Socket
	IO::Socket::INET
	IO::Socket::INET6
	IO::Socket::IP
	MIME::Base64
	Net::LibIDN
	PerlIO
	Scalar::Util
	Socket
	Time::Local
	);

diag("\n\nThese tests were run using:\n");
foreach my $module (@module) {
	my $loaded = eval("require $module") || next;
	my $revnum = $loaded ? $module->VERSION : "\t\tn/a";
	diag sprintf "\t%-25s  %s", $module, $revnum || '?';
}

diag("set environment variable NET_DNS_DEBUG to get all versions\n\n");


use_ok('Net::DNS');

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

