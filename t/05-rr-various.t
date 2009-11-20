# $Id$   -*-perl-*-
# Contains a number of additional test for RR related functionality


use Test::More;
use strict;
use Net::DNS;
use vars qw( $HAS_DNSSEC $HAS_DLV $HAS_NSEC3 $HAS_NSEC3PARAM);


plan tests => 6;


is ( Net::DNS::stripdot ('foo\\\\\..'),'foo\\\\\.', "Stripdot does its magic in precense of escapes test 1");
is ( Net::DNS::stripdot ('foo\\\\\.'),'foo\\\\\.', "Stripdot does its magic in precense of escapes test 2");
is ( Net::DNS::stripdot(''),'',"Stripdot handles empty strings as it should");


# rt.cpan.org 41071
my $pkt1 = Net::DNS::Packet->new('e3.example.com','AAAA','IN');
$pkt1->push( answer => Net::DNS::RR->new(
name => 'e3.example.com',
type => 'AAAA',
address => 'CAFE:BABE::1'
));
my $pkt2 = Net::DNS::Packet->new( \$pkt1->data );
is(($pkt1->answer)[0]->string,($pkt2->answer)[0]->string,"New from string and new from hash creation ");

is(($pkt1->answer)[0]->address,"cafe:babe:0:0:0:0:0:1","Lets have cafe:babe:0:0:0:0:0:1");




#rt 49035

my $string = '5.5.5.5 1200 IN NAPTR    100 100 "u" "E2U+X-ADDRESS" "!^(.*)$!data:,CN=East test;ST=CT;C=United States;uid=ast1;intrunk=dms500!" .';
my $newrr1 = Net::DNS::RR->new("$string");


my $newrr2 = Net::DNS::RR->new(name=> '5.5.5.5',
                              ttl=>  1200,
                              class=> 'IN',
                              type => 'NAPTR',
                              order => '100',
                              preference => '100',
                              flags =>  'u',
                              service =>  'E2U+X-ADDRESS',
                              regexp => '!^(.*)$!data:,CN=East test;ST=CT;C=United States;uid=ast1;intrunk=dms500!',
                              replacment => '.',
                              rdlength => 0,
                              rdata => '',
        );



is($newrr1->string,$newrr2->string, "Failed to parse ". $string);
