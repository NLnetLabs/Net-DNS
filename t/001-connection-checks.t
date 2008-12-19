# $Id$ -*-perl-*-

my $has_inet6;
use Test::More;
use strict;
use Socket;
use Data::Dumper;
use Net::DNS;
my $IPv4_available;
my $IPv6_available;

BEGIN{
    plan tests => 1;
    
    ok(1,"Dummy");
    
    $IPv4_available=(-e 't/online.enabled');
    $IPv6_available= (-e 't/IPv6.enabled');

    diag("\n\nExecuting heuristic to see if have unlimited view of the Internet");
    diag("If the heuristic fails this could have various reasons probably having");
    diag("with bugs in Net::DNS");
    diag("\n\n");
}





sub disable_ipv4 {
    diag  "\t\t IPv4 Online tests disabled.";
    open(DISABLED, ">t/online.disabled") || die "Can't touch ./t/online.disabled $!";
    close(DISABLED)                     || die "Can't touch ./t/online.disabled $!";
    $IPv4_available=0;
}






sub disable_ipv6 {
    diag  "\t\t IPv6 Online tests disabled.";
    open(DISABLED, ">t/IPv6.disabled") || die "Can't touch ./t/IPv6.disabled $!";
    close(DISABLED)                     || die "Can't touch ./t/IPv6.disabled $!";
    $IPv6_available=0;
}





BEGIN {
    exit unless (-e 't/IPv6.enabled') ;
    if 	( eval {require IO::Socket::INET6; IO::Socket::INET6->VERSION("2.01");}) {
	
	my    $tstsock = IO::Socket::INET6->new(
	    LocalPort => 5363,
	    Proto => "udp",
	    LocalAddr => '::1'
	    ) ;
	
	
	
	if($tstsock){
	    $IPv6_available=1;
	}else{
	    diag "\n\n\t\tFailed to bind to ::1\n\t\t$!\n\n".
		"\t\tWe assume there is no IPv6 connectivity and skip the IPv6 tests\n\n";
	    disable_ipv6 ();    
	};
	
    } else {
	disable_ipv6 ();    
    }
}


my $answer;
my $A_address;
my $AAAA_address;
my $res= Net::DNS::Resolver->new ( retry => 2,
				   udp_timeout => 2,
    );
$res->debug(1);
my $nsanswer=$res->send("net-dns.org","NS","IN");

if (! defined($nsanswer)){
    diag ("Error querying local resolver: " . $res->errorstring);
    diag "We are canceling all test";
    diag "\t\t This is not an error in Net::DNS \n";
    disable_ipv4() &&     disable_ipv6() && exit;    
}


foreach my $ns ($nsanswer->answer){
    next if $ns->nsdname !~ /net-dns\.org$/i; # Use nlnetlabs
    my $a_answer=$res->send($ns->nsdname,"A","IN");
    next unless defined $a_answer;
    next if ($a_answer->header->ancount == 0);
    $A_address=($a_answer->answer)[0]->address;
    undef($a_answer);
     $a_answer=$res->send($ns->nsdname,"AAAA","IN");
    next unless defined $a_answer;
    next if ($a_answer->header->ancount == 0);
    $AAAA_address=($a_answer->answer)[0]->address;
    diag ("\n\t Will try to connect to  ". $ns->nsdname . " ($A_address" .( $IPv6_available?" or $AAAA_address)":")"));
    last;
}


if ( $IPv4_available ){
    $res->nameservers($A_address);
    $answer=$res->send("connection-test.t.net-dns.org","TXT","IN");
    if( ! defined ($answer)  ){
	diag "\n\t\t Failed querying $A_address: " . $res->errorstring ;
	diag "\n\t\t It could be you do not have global IP connectivity' \n" ;
	diag "\t\t This is not an error in Net::DNS \n";
	diag "\t\t You can confirm this by trying 'ping ".$A_address."' \n\n";
	diag "\t\t Alternatively the Nameserver running on ".$A_address." is currently down' \n\n";
	disable_ipv4 ();    
    }elsif ($answer->header->ancount != 1 ||
	    ($answer->answer)[0]->type ne "TXT" ||
	    ($answer->answer)[0]->txtdata ne "connection-test succes"){
	diag "\n\t\t Received an unexpected answer to a query for" ;
	diag  "\t\t connection-test.t.net-dns.org TXT IN" ;
	diag  "\t\t directed to ".$A_address."' \n\n";
	disable_ipv4 ();    
    }
}

if ( $IPv6_available ){
    $res->nameservers($AAAA_address);
    $answer=$res->send("connection-test.t.net-dns.org","TXT","IN");
    if( ! defined ($answer)  ){
	diag "\n\t\t Failed querying $AAAA_address: " . $res->errorstring ;
	diag "\n\t\t It could be you do not have global IP connectivity' \n" ;
	diag "\t\t This is not an error in Net::DNS \n";
	diag "\t\t You can confirm this by trying 'ping6 ".$AAAA_address."' \n\n";
	diag "\t\t Alternatively the Nameserver running on ".$AAAA_address." is currently down' \n\n";
	disable_ipv6 ();    
    }elsif ($answer->header->ancount != 1 ||
	    ($answer->answer)[0]->type ne "TXT" ||
	    ($answer->answer)[0]->txtdata ne "connection-test succes"){
	diag "\n\t\t Received an unexpected answer to a query for" ;
	diag  "\t\t connection-test.t.net-dns.org TXT IN" ;
	diag  "\t\t directed to ".$AAAA_address."' \n\n";
	disable_ipv6 ();    
    }

}
diag("\n\n");
$IPv4_available && diag ("IPv4 appears to be available");
$IPv6_available && diag ("IPv6 appears to be available");






