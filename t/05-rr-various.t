# $Id$   -*-perl-*-
# Contains a number of additional test for RR related functionality


use Test::More;
use strict;
use Net::DNS;
use vars qw( $HAS_DNSSEC $HAS_DLV $HAS_NSEC3 $HAS_NSEC3PARAM);


plan tests => 3;


is ( Net::DNS::stripdot ('foo\\\\\..'),'foo\\\\\.', "Stripdot does its magic in precense of escapes test 1");
is ( Net::DNS::stripdot ('foo\\\\\.'),'foo\\\\\.', "Stripdot does its magic in precense of escapes test 2");



# rt.cpan.org 41071
my $pkt1 = Net::DNS::Packet->new('e3.example.com','AAAA','IN');
$pkt1->push( answer => Net::DNS::RR->new(
name => 'e3.example.com',
type => 'AAAA',
address => 'CAFE:BABE::1'
));
my $pkt2 = Net::DNS::Packet->new( \$pkt1->data );
is(($pkt1->answer)[0]->string,($pkt2->answer)[0]->string,"New from string and new from hash creation ");




#--------------
#
# Some test that test on appropriate normalization of internal storage
# when using new_from_hash



