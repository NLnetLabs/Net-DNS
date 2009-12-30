# $Id$	-*-perl-*-

use strict;
use Test::More tests => 204;


BEGIN {
	use_ok('Net::DNS::Question');
}


t2: {
	my $fqdn = 'example.com.';
	my $question = new Net::DNS::Question( $fqdn, 'A', 'IN' );
	isa_ok( $question, 'Net::DNS::Question', 'object returned by new() constructor' );

	my $string   = $question->string;
	my $expected = "$fqdn\tIN\tA";
	is( $string, $expected, '$question->string returns text representation of object' );

	my $test = 'new() argument undefined or absent';
	is( new Net::DNS::Question( $fqdn, 'A',   undef )->string, $expected, "$test\t( $fqdn,\tA,\tundef\t)" );
	is( new Net::DNS::Question( $fqdn, 'A',   ()    )->string, $expected, "$test\t( $fqdn,\tA,\t\t)" );
	is( new Net::DNS::Question( $fqdn, undef, 'IN'  )->string, $expected, "$test\t( $fqdn,\tundef,\tIN\t)" );
	is( new Net::DNS::Question( $fqdn, (),    'IN'  )->string, $expected, "$test\t( $fqdn,\t\tIN\t)" );
	is( new Net::DNS::Question( $fqdn, undef, undef )->string, $expected, "$test\t( $fqdn,\tundef,\tundef\t)" );
	is( new Net::DNS::Question( $fqdn, (),    ()    )->string, $expected, "$test\t( $fqdn \t\t\t)" );
}


t10: {
	my $test = 'new() arguments in zone file order';
	my $fqdn = 'example.com.';
	foreach my $class (qw(IN CLASS1 ANY)) {
		foreach my $type (qw(A TYPE1 ANY)) {
			my $testcase = new Net::DNS::Question( $fqdn, $class, $type )->string;
			my $expected = new Net::DNS::Question( $fqdn, $type,  $class )->string;
			is( $testcase, $expected, "$test\t( $fqdn,\t$class,\t$type\t)" );
		}
	}
}



#19	parse() class constructor method must return object of appropriate class
my $example = Net::DNS::Question->new('example.com');
my $example_data = pack("C a* C a* C n2", 7, 'example', 3, 'com', 0, 1, 1);
my $question = Net::DNS::Question->parse(\$example_data, 0);
isa_ok($question, 'Net::DNS::Question', 'parse() object');
is_deeply($question, $example, 'parse() object matches input data' );

#	parse method called in list context returns (object,offset) pair
my ($object, $next) = Net::DNS::Question->parse(\$example_data, 0);
isa_ok($object, 'Net::DNS::Question', 'in list context, parse() returned object');
is($next, length $example_data, 'in list context, parse() provides offset to next data');

#	parse method raises exception for incomplete data
my $truncated = $example_data;
while ( chop $truncated ) {
	my ($object, $offset) = eval{ Net::DNS::Question->parse(\$truncated, 0) };
	like(lc $@,	'/exception/',	'exception raised for incomplete data' );
}

#	parse method raises exception for unparsable data
my $empty = '';
my $circular = pack("C a* n3", 7, 'invalid', 0xc000, 1, 1);
my $corrupt = pack("C a* n3", 7, 'invalid', 0xc100, 1, 1);
foreach my $unparsable ($empty, $circular, $corrupt) {
	my ($object, $offset) = eval{ Net::DNS::Question->parse(\$unparsable, 0) };
	like(lc $@,	'/exception/',	'exception raised for unparsable data' );
}



#	data method produces binary representation of object
my $domain = 'example.com';
foreach my $class ( qw(CH IN ANY) ) {
	foreach my $type ( qw(A AAAA MX NS SOA ANY) ) {
		my $packet = Net::DNS::Packet->new();
		my $example = Net::DNS::Question->new($domain, $type, $class);
		my $example_data = $example->data($packet, 0);
		my $question = Net::DNS::Question->parse(\$example_data, 0);
		is_deeply($question, $example, $example->string );
	}
}



#	Every access method able to read and modify corresponding variable
my $q = Net::DNS::Question->new();
foreach my $method ( qw(qname qtype qclass zname ztype zclass) ) {
	foreach my $value ('', 'P', 'Q.', '.') {
		$q->$method(undef);
		my $initial = $q->$method;
		my $written = $q->$method($value);
		my $read = $q->$method;
		isnt($read,	$initial,	"call $method('$value')" );
		is($read,	$written,	"$method() is '$written'" );
	}
}



#	new() interprets IPv4 address as PTR query
is(Net::DNS::Question->new('10.2.3.4')->string,	"4.3.2.10.in-addr.arpa.\tIN\tPTR",	'IPv4 PTR query' );
is(Net::DNS::Question->new('10.0.0.0', 'NS')->qtype,	'NS',	'NS query in IPv4 space' );
is(Net::DNS::Question->new('10.0.0.0', 'SOA')->qtype,	'SOA',	'SOA query in IPv4 space' );
is(Net::DNS::Question->new('10.0.0.0', 'ANY')->qtype,	'ANY',	'ANY query in IPv4 space' );
foreach my $n ( 1, 123 ) {
	my $ip4 = "$n.$n.$n.$n";
	my $rev = "$ip4.in-addr.arpa";
	is(Net::DNS::Question->new($ip4)->qname,		$rev,	'IPv4 address' );
	is(Net::DNS::Question->new("::ffff:$ip4")->qname,	$rev,	'IP6v4 syntax' );
}



#	new() interprets IPv4 prefix as reverse query of length sufficient to contain specified bits
is(Net::DNS::Question->new(0)->qname,		'0.in-addr.arpa',	'IPv4 prefix 0' );
is(Net::DNS::Question->new(10)->qname,		'10.in-addr.arpa',	'IPv4 prefix 10' );
is(Net::DNS::Question->new('10.2')->qname,	'2.10.in-addr.arpa',	'IPv4 prefix 10.2' );
is(Net::DNS::Question->new('10.2.3')->qname,	'3.2.10.in-addr.arpa',	'IPv4 prefix 10.2.3' );
foreach my $n ( 1..32 ) {
	my $m = (($n + 7)>>3)<<3;
	my $ip4 = '10.2.3.4';
	my $equivalent = Net::DNS::Question->new("$ip4/$m")->qname;
	is(Net::DNS::Question->new("$ip4/$n")->qname,	$equivalent,	"IPv4 prefix /$n" );
}



#	new() interprets IPv6 address as PTR query
is(Net::DNS::Question->new('1:2:3:4:5:6:7:8')->string,
	"8.0.0.0.7.0.0.0.6.0.0.0.5.0.0.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.ip6.arpa.\tIN\tPTR",	'IPv6 PTR query' );
is(Net::DNS::Question->new('::')->string,
	"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.\tIN\tPTR",	'IPv6 PTR query' );
is(Net::DNS::Question->new('::', 'NS')->qtype,	'NS',		'NS query in IPv6 space' );
is(Net::DNS::Question->new('::', 'SOA')->qtype,	'SOA',		'SOA query in IPv6 space' );
is(Net::DNS::Question->new('::', 'ANY')->qtype,	'ANY',		'ANY query in IPv6 space' );
is(Net::DNS::Question->new('::x')->string, "::x.\tIN\tA",	'::x (not IPv6)' );


#	new() interprets IPv6 prefix as reverse query of length sufficient to contain specified bits
is(Net::DNS::Question->new(':')->qname, Net::DNS::Question->new('0:0')->qname, 'IPv6 prefix :' );
is(Net::DNS::Question->new('1:')->qname, Net::DNS::Question->new('1:0')->qname, 'IPv6 prefix 1:' );
is(Net::DNS::Question->new('1:2')->qname, Net::DNS::Question->new('1:2:3:4:5:6:7:8/32')->qname, 'IPv6 prefix 1:2' );
is(Net::DNS::Question->new('1:2:3')->qname, Net::DNS::Question->new('1:2:3:4:5:6:7:8/48')->qname, 'IPv6 prefix 1:2:3' );
is(Net::DNS::Question->new('1:2:3:4')->qname, Net::DNS::Question->new('1:2:3:4:5:6:7:8/64')->qname, 'IPv6 prefix 1:2:3:4' );
foreach my $n ( 1..8, 124..128 ) {
	my $m = (($n + 3)>>2)<<2;
	my $ip6 = '1234:5678:9012:3456:7890:1234:5678:9012';
	my $equivalent = Net::DNS::Question->new("$ip6/$m")->qname;
	is(Net::DNS::Question->new("$ip6/$n")->qname,	$equivalent,	"IPv6 prefix /$n" );
}


#	Abbreviated IPv6 address expands to same length as canonical form
my $canonical = length Net::DNS::Question->new('1:2:3:4:5:6:7:8')->qname;
foreach my $i (reverse 0 .. 6) {
	foreach my $j ($i+3 .. 9) {
		my $ip6 = join(':', 1..$i).'::'.join(':', $j..8);
		is(length Net::DNS::Question->new("$ip6")->qname, $canonical, "expand $ip6" );
	}
}

