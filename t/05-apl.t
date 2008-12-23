# $Id: 01-resolver.t 479 2005-07-31 14:19:41Z olaf $  -*-perl-*-

use Test::More tests => 18;
use strict;
use Data::Dumper;

#### 
##
## Some APL routines.

use Net::DNS;
use Net::DNS::RR::APL;



foreach my $apitem qw( 1:192.168.32.0/21 !1:192.168.32.0/21 2:FF00:0:0:0:0:0:0:0/8){
    my $object=Net::DNS::RR::APL::ApItem->new($apitem);    
    is ( $object->string, $apitem, "String read/write correct for $apitem");
}

foreach my $apitem qw( 1:192.168.32.0.3/21 !1:192.168.32.0+21 4:FF00:0:0:0:0:0:0:0/8){
    my $object=Net::DNS::RR::APL::ApItem->new($apitem);    
    diag ($object->string)    unless( ok ( !defined ($object), "Incorrect format not parsed")); 
}




my $UUencodedData='
 00 01 1a 03 c0 a8 2a
 00 01 1a 04 c0 a8 2a 40 
 00 01 19 84 c0 a8 2a 80 
 00 01 04 01 e0 
 00 02 08 01 ff
';

$UUencodedData =~ s/\s*//g;
my $datadata = pack('H*',$UUencodedData);
my $dummy;
my ($apitem,$offset)=Net::DNS::RR::APL::ApItem->new_from_wire($datadata, 0);
is(lc $apitem->string,lc "1:192.168.42.0/26","1:192.168.42.0/26 compares");
# diag(unpack("H*",$apitem->rdata));
($apitem,$dummy)=Net::DNS::RR::APL::ApItem->new_from_wire($apitem->rdata(), 0);
is(lc $apitem->string,lc "1:192.168.42.0/26","1:192.168.42.0/26 compares");


($apitem,$offset)=Net::DNS::RR::APL::ApItem->new_from_wire($datadata, $offset);
is(lc $apitem->string,lc "1:192.168.42.64/26","1:192.168.42.64/26 compares");
# diag(unpack("H*",$apitem->rdata));
($apitem,$dummy)=Net::DNS::RR::APL::ApItem->new_from_wire($apitem->rdata(), 0);
is(lc $apitem->string,lc "1:192.168.42.64/26","1:192.168.42.64/26 compares");



($apitem,$offset)=Net::DNS::RR::APL::ApItem->new_from_wire($datadata, $offset);
is(lc $apitem->string,lc "!1:192.168.42.128/25","1:192.168.42.128/25 compares");
# diag(unpack("H*",$apitem->rdata));
($apitem,$dummy)=Net::DNS::RR::APL::ApItem->new_from_wire($apitem->rdata(), 0);
is(lc $apitem->string,lc "!1:192.168.42.128/25","1:192.168.42.128/25 compares");



($apitem,$offset)=Net::DNS::RR::APL::ApItem->new_from_wire($datadata, $offset);
is(lc $apitem->string,lc "1:224.0.0.0/4","1:224.0.0.0/4 compares");
# diag(unpack("H*",$apitem->rdata));
($apitem,$dummy)=Net::DNS::RR::APL::ApItem->new_from_wire($apitem->rdata(), 0);
is(lc $apitem->string,lc "1:224.0.0.0/4","1:224.0.0.0/4 compares");


($apitem,$offset)=Net::DNS::RR::APL::ApItem->new_from_wire($datadata, $offset);
is(lc $apitem->string,lc "2:FF00:0:0:0:0:0:0:0/8","2:FF00:0:0:0:0:0:0:0/8 compares");
# diag(unpack("H*",$apitem->rdata));
($apitem,$dummy)=Net::DNS::RR::APL::ApItem->new_from_wire($apitem->rdata(), 0);
is(lc $apitem->string,lc "2:FF00:0:0:0:0:0:0:0/8","2:FF00:0:0:0:0:0:0:0/8 compares");



my $UUencodedPacket='
35 0b 81 80 00 01
00 01 00 00 00 00 03 61  70 6c 07 6e 65 74 2d 64
6e 73 03 6f 72 67 00 00  2a 00 01 c0 0c 00 2a 00
01 00 00 00 64 00 21 00  01 1a 03 c0 a8 2a 00 01
1a 04 c0 a8 2a 40 00 01  19 04 c0 a8 2a 80 00 01
04 01 e0 00 02 08 01 ff                         
';
$UUencodedPacket =~ s/\s*//g;
my  $packetdata = pack('H*',$UUencodedPacket);
my $packet     = Net::DNS::Packet->new(\$packetdata);
is(($packet->answer)[0]->rdatastr,"1:192.168.42.0/26 1:192.168.42.64/26 1:192.168.42.128/25 1:224.0.0.0/4 2:ff00:0:0:0:0:0:0:0/8","Packet content parsed");
    
my $apl= Net::DNS::RR->new("foo.example.             IN APL 1:192.168.32.0/21 !1:192.168.38.0/28");
is($apl->rdatastr,"1:192.168.32.0/21 !1:192.168.38.0/28", "String parsing of APL RR");


foreach my $ap ($apl->aplist()){
    print $ap->negation()?"!":"";		
    print $ap->address();		
    print $ap->prefix(). " ";
    }





