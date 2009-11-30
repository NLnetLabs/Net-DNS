# $Id$   -*-perl-*-

use Test::More;
use strict;
use t::TestData;
use Net::DNS;
use vars qw( $HAS_DNSSEC $HAS_DLV $HAS_NSEC3 $HAS_NSEC3PARAM);
use Data::Dumper;


my $keypathrsa="Kexample.com.+005+24866.private";
my $rsakeyrr;

BEGIN {

	my $methods=0;
	my $number=0;
	foreach my $rr ( @rrs ){
	    $methods += keys(%$rr);
	}
	diag "Number of RRs: ".  @rrs . " Number of methods: ".$methods."\n";
	$number=  3 +  2*$methods +  6*scalar @rrs;


    if(
	eval {require Net::DNS::SEC;}
	){
	$HAS_DNSSEC=1;
	if ( 
	    defined($Net::DNS::SEC::SVNVERSION) && 
	    $Net::DNS::SEC::SVNVERSION > 619 
	    )
	{
	    $HAS_NSEC3PARAM=1;
	    plan tests => $number;  # Hook
	}else{
	    plan tests => $number;
	}
    }else{
	$HAS_DNSSEC=0;

	plan tests => $number- @rrs -1 ;
    }
};




if ($HAS_DNSSEC){  # Create key material    
    diag "The suite will run additonal DNSSEC tests";
    my $privrsakey= << 'ENDRSA' ;
Private-key-format: v1.2
Algorithm: 5 (RSASHA1)
Modulus: osG7zULAQoU3HxVnQl0dj8pLCcxA4ZQk9lgSzd+Q5GvhQYPS4vtnBRvwQDPTckfINqHYbxLQBZGYyl3n0ZQ0W5GDUlnDkeKk+2fe0UIbArY+xkODYGBmv6VGDk1K0kc7mH6cYHUciEtPMdyzYa9hIPfPDp2IE0+BRpr3hPkRnLE=
PublicExponent: Aw==
PrivateExponent: bIEn3iyALFjPag5E1ui+X9wyBogrQQ1t+ZAMiT+17Z1A1lfh7KeaA2f1gCKM9tqFecE69Lc1WQu7MZPv4Q14O/uDO/th5aF6oUL6kYYiSkbmxZ138w6g/PRh+Y/F135Hz8nVyTLrbmo+l5tjiaN5LOgUjvYYwSR3k1FFhgW3zks=
Prime1: zF8a/5xhYpBZH7uVB0xxuo7FbepslQnCSudXRd+1KFmpJ6z4XSDEJVl/XngaVw4j4IvHL9FpjF8JkH1PUn2c7Q==
Prime2: y99dYRRYDdywY6th8ZshkVXYaWUHNWuB68vAr8JZ4XY3qC66S5qehpfPFSX44x05uyRw/JGIDG7gEJHsngBKVQ==
Exponent1: iD9nVRLrlwrmFSe4r4hL0bSDnpxIY1vW3Jo6LpUjcDvGGnNQPhXYGOZU6aVm5LQX6wfaH+DxCD9btajfjFO98w==
Exponent2: h+o+QLg6s+h1l8eWoRIWYOPlm5ivePJWnTKAdSw766QlGsnRh7xprw/fY26l7L4mfML1/bZasvSVYGFIaVWG4w==
Coefficient: BV4xfdcDiyLKBr6647EUocgAziN3qfVsfJc0DdJjYW3VnuECVvNo8Q2ehAYTAwdzNRjBhwB7ZV3Mi6+S8OXFTQ==
ENDRSA


open (RSA,">$keypathrsa") or die "Could not open $keypathrsa";
    print RSA $privrsakey;
    close(RSA);
        
 $rsakeyrr=new Net::DNS::RR ("example.com. IN DNSKEY 256 3 5 AQOiwbvNQsBChTcfFWdCXR2PyksJzEDhlCT2WBLN35Dka+FBg9Li+2cF G/BAM9NyR8g2odhvEtAFkZjKXefRlDRbkYNSWcOR4qT7Z97RQhsCtj7G Q4NgYGa/pUYOTUrSRzuYfpxgdRyIS08x3LNhr2Eg988OnYgTT4FGmveE +RGcsQ==

");
    
    ok( $rsakeyrr, 'RSA public key created');     # test 5

    if ($HAS_DLV){
	diag("DLV Supported in this version of Net::DNS::SEC");
	my $dlv=new Net::DNS::RR ("dskey.example.com. 86400 IN DS 60485 5 2 ( 
                                                D4B7D520E7BB5F0F67674A0C
                                                CEB1E3E0614B93C4F9E99B83
                                                83F6A1E4469DA50A )");    
	ok( $dlv, "DLV RR created");
    }


    if ($HAS_NSEC3PARAM){
	diag("NSEC3PARAM / NSEC3 Supported in this version of Net::DNS::SEC (no tests yet)");
    }


}





BEGIN { use_ok('Net::DNS'); }

#------------------------------------------------------------------------------
# Canned data.
#------------------------------------------------------------------------------

my $name			= "foo.example.com";
my $class			= "IN";
my $ttl				= 43200;




#------------------------------------------------------------------------------
# Create the packet and signatures (if DNSSEC is available.)
#------------------------------------------------------------------------------

my @rrsigs;
my $packet = Net::DNS::Packet->new($name);
ok($packet,         'Packet created');


# @rrs is exported from t::TestData
foreach my $data (@rrs) {
    my $RR=Net::DNS::RR->new(
	   name => $name,
	   ttl  => $ttl,
	   %{$data});


    # Test if new-from-hash strips dots appropriatly for all subtypes
    foreach my $meth (keys %{$data}) {
	my $i=$data->{$meth};
	$i =~ s/\.$// unless $i eq ".";
	if ( $data->{'type'} eq "HIP" && $meth eq "rendezvousservers"  ) {
	    ok ( is_deeply ($RR->$meth(), $i ),"HIP -  $meth() correct for hash based creation (HIP specific test)");
	    use Data::Dumper;
	    next;
	}
	is( $RR->$meth(), $i , $data->{"type"}." - $meth() correct for hash based creation");
    }
	


       if ($HAS_DNSSEC){
	   my $sigrr= create Net::DNS::RR::RRSIG( [ $RR ],
						  $keypathrsa,
						  (
						   ttl => 360, 
						   sigval => 100,
						  ));
#	   $sigrr->print;
	   push  @rrsigs, $sigrr;
       }
       

       $packet->push('answer', $RR );
}


#------------------------------------------------------------------------------
# Re-create the packet from data.
#------------------------------------------------------------------------------

my $data = $packet->data;
ok($data,            'Packet has data after pushes');

undef $packet;
$packet = Net::DNS::Packet->new(\$data);

ok($packet,          'Packet reconstructed from data');

my @answer = $packet->answer;

ok(@answer && @answer == @rrs, 'Packet returned correct answer section');





while (@answer and @rrs) {
	my $data = shift @rrs;
	my $rr   = shift @answer;
	my $type = $data->{'type'};

	ok($rr,                         "$type - RR defined");    
	is($rr->name,    $name,    	"$type - name() correct");         
	is($rr->class,   $class,      	"$type - class() correct");  
	is($rr->ttl,     $ttl,        	"$type - ttl() correct");              
 
	foreach my $meth (keys %{$data}) {
	    my $i=$data->{$meth};
	    $i =~ s/\.$//;
	    next if ( $type eq "IPSECKEY" && $meth eq "gateway"  && $rr->{"gatetype"} != 3 ) ;
	    next if ( $type eq "HIP" && $meth eq "rendezvousservers"  ) ;
	    is($rr->$meth(), $i , "$type - $meth() correct");
	}
	
	my $rr2 = Net::DNS::RR->new($rr->string);
	is($rr2->string, $rr->string,   "$type - Parsing from string works");
	if ($HAS_DNSSEC){
	    my $rrsig=shift @rrsigs;
	    ok($rrsig->verify([ $rr ], $rsakeyrr), "RR of type ".$type." signature creation/validation cycle");
	}
	
}






unlink($keypathrsa);
