# $Id$

use Test::More tests => 58;
use strict;

BEGIN { use_ok('Net::DNS'); }

my $packet = new Net::DNS::Packet(qw(. NS IN));
my $header = $packet->header;
ok( $header->isa('Net::DNS::Header'), 'packet->header object' );


sub waggle {
	my $object = shift;
	my $attribute = shift;
	my @sequence = @_;
	for my $value (@sequence) {
		my $change = $object->$attribute($value);
		my $stored = $object->$attribute();
		is($stored, $value, "expected value after header->$attribute($value)");
	}
}


my $newid = new Net::DNS::Packet->header->id;
waggle( $header, 'id', $header->id, $newid, $header->id );

waggle( $header, 'opcode', qw(STATUS UPDATE QUERY) );
waggle( $header, 'rcode', qw(REFUSED FORMERR NOERROR) );

waggle( $header, 'qr', 1, 0, 1, 0 );
waggle( $header, 'aa', 1, 0, 1, 0 );
waggle( $header, 'tc', 1, 0, 1, 0 );
waggle( $header, 'rd', 0, 1, 0, 1 );
waggle( $header, 'ra', 1, 0, 1, 0 );
waggle( $header, 'ad', 1, 0, 1, 0 );
waggle( $header, 'cd', 1, 0, 1, 0 );


#
#  Is $header->string remotely sane?
#
like($header->string, '/opcode = QUERY/', 'string() has opcode correct');
like($header->string, '/qdcount = 1/',    'string() has qdcount correct');
like($header->string, '/ancount = 0/',    'string() has ancount correct');
like($header->string, '/nscount = 0/',    'string() has nscount correct');
like($header->string, '/arcount = 0/',    'string() has arcount correct');


#
# Check that the aliases work
#
my $rr = new Net::DNS::RR('example.com. 10800 A 192.0.2.1');
my @rr = ( $rr, $rr );
$packet->push( prereq	=> nxrrset('foo.example.com. A'), $rr );
$packet->push( update	=> $rr, @rr);
$packet->push( additional => @rr, @rr);

is($header->zocount, $header->qdcount, 'zocount value matches qdcount');
is($header->prcount, $header->ancount, 'prcount value matches ancount');
is($header->upcount, $header->nscount, 'upcount value matches nscount');
is($header->adcount, $header->arcount, 'adcount value matches arcount');


my $data = $packet->data;

my $packet2 = new Net::DNS::Packet(\$data);

my $string = $packet->header->string;

is($packet2->header->string, $string, 'encode/decode transparent');


SKIP: {
	my $edns = $header->edns;
	ok( $edns->isa('Net::DNS::RR::OPT'), 'header->edns object' );

	skip( 'EDNS header extensions not supported', 8 ) unless $edns->isa('Net::DNS::RR::OPT');

	waggle( $header, 'do', 0, 1, 0, 1 );
	waggle( $header, 'rcode', qw(BADVERS BADMODE BADNAME) );

	my $packet = new Net::DNS::Packet();			# empty EDNS size solicitation
	my $udplim = 1280;
	$packet->edns->size($udplim);
	my $encoded = $packet->data;
	my $decoded = new Net::DNS::Packet(\$encoded);
	is($decoded->edns->size, $udplim, 'EDNS size request assembled correctly');
}

print "\n$string\n";

