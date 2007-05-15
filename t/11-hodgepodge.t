
# $Id$		 -*-perl-*-



use Test::More;
use strict;
use Data::Dumper;
use Net::DNS::Packet;
plan tests => 3;



my $packet=Net::DNS::Packet->new();
my $question = Net::DNS::Question->new("wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww.com", "MX", "IN");

my ($data,$error)= $question->data($packet);
is( $error, "length of wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww is larger than 63 octets; see RFC1035 section 2.3.1", "Approriate error returned");

undef $question;
undef $packet;

$packet=Net::DNS::Packet->new();
$question = Net::DNS::Question->new("wwwwwwwwwwwwwwww.com", "MX", "IN");
($data,$error)= $question->data($packet);
ok (defined ($data), "Data defined");
ok (! defined ($error), "Error not defined");
