# $Id: 04-packet.t,v 1.3 1997/06/08 06:42:47 mfuhr Exp $

BEGIN { $| = 1; print "1..18\n"; }
END {print "not ok 1\n" unless $loaded;}

use Net::DNS;

$loaded = 1;
print "ok 1\n";

$domain = "foo.com";
$type   = "MX";
$class  = "IN";

$packet = new Net::DNS::Packet($domain, $type, $class);
print "not " unless defined $packet;
print "ok 2\n";

print "not " unless defined $packet->header;
print "ok 3\n";

@question = $packet->question;
print "not " unless (defined @question)  && ($#question == 0);
print "ok 4\n";

@answer = $packet->answer;
print "not " if defined @answer;
print "ok 5\n";

@authority = $packet->authority;
print "not " if defined @authority;
print "ok 6\n";

@additional = $packet->additional;
print "not " if defined @additional;
print "ok 7\n";

$packet->push("answer", new Net::DNS::RR(
	Name    => "a1.bar.com",
	Type    => "A",
	Address => "10.0.0.1"));
print "not " unless $packet->header->ancount == 1;
print "ok 8\n";

$packet->push("answer", new Net::DNS::RR(
	Name    => "a2.bar.com",
	Type    => "A",
	Address => "10.0.0.2"));
print "not " unless $packet->header->ancount == 2;
print "ok 9\n";

$packet->push("authority", new Net::DNS::RR(
	Name    => "a3.bar.com",
	Type    => "A",
	Address => "10.0.0.3"));
print "not " unless $packet->header->nscount == 1;
print "ok 10\n";

$packet->push("authority", new Net::DNS::RR(
	Name    => "a4.bar.com",
	Type    => "A",
	Address => "10.0.0.4"));
print "not " unless $packet->header->nscount == 2;
print "ok 11\n";

$packet->push("additional", new Net::DNS::RR(
	Name    => "a5.bar.com",
	Type    => "A",
	Address => "10.0.0.5"));
print "not " unless $packet->header->adcount == 1;
print "ok 12\n";

$packet->push("additional", new Net::DNS::RR(
	Name    => "a6.bar.com",
	Type    => "A",
	Address => "10.0.0.6"));
print "not " unless $packet->header->adcount == 2;
print "ok 13\n";

$data = $packet->data;
$packet2 = new Net::DNS::Packet(\$data);
print "not " unless defined $packet2;
print "ok 14\n";

print "not " unless $packet2->header->qdcount == 1;
print "ok 15\n";

print "not " unless $packet2->header->ancount == 2;
print "ok 16\n";

print "not " unless $packet2->header->nscount == 2;
print "ok 17\n";

print "not " unless $packet2->header->adcount == 2;
print "ok 18\n";
