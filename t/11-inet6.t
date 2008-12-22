# $Id$ -*-perl-*-



use Test::More; 
use strict;





BEGIN {
	if (-e 't/IPv6.enabled' && ! -e 't/IPv6.disabled' ) {
		plan tests => 10;
	} else {
		plan skip_all => 'Online tests disabled.';
		exit;
	}
}



my $answer;
my $res= Net::DNS::Resolver->new;
;
my $res2;

my $AAAA_address;
my $A_address;


# If there is IPv6 transport only then this works too.
my $nsanswer=$res->send("net-dns.org","NS","IN");
is (($nsanswer->answer)[0]->type, "NS","Preparing  for v6 transport, got NS records for net-dns.org");

my $found_ns=0;
foreach my $ns ($nsanswer->answer){
    next if $ns->nsdname !~ /net-dns\.org$/i; # User net-dns.org only
    my $aaaa_answer=$res->send($ns->nsdname,"AAAA","IN");
    next if ($aaaa_answer->header->ancount == 0);
    is (($aaaa_answer->answer)[0]->type,"AAAA", "Preparing  for v6 transport, got AAAA records for ". $ns->nsdname);
    $AAAA_address=($aaaa_answer->answer)[0]->address;
    $found_ns=1;
    diag ("\n\t\t Will try to connect to  ". $ns->nsdname . " ($AAAA_address)");
    last;
}

ok(1,"Dummy test: No AAA Records found, we will skip some other tests") unless $found_ns;

$res->nameservers($AAAA_address);
#$res->print;
$answer=$res->send("net-dns.org","SOA","IN");

is (($answer->answer)[0]->type, "SOA","Query over udp6 succeeded");



$res->usevc(1);
$res->force_v4(1);
# $res->print;
# $res->debug(1);
$answer=$res->send("net-dns.org","SOA","IN");
is ($res->errorstring,"no nameservers","Correct errorstring when forcing v4");


$res->force_v4(0);
$answer=$res->send("net-dns.org","NS","IN");
if ($answer){
    is (($answer->answer)[0]->type, "NS","Query over tcp6  succeeded");
}else{
    diag "You can safely ignore the following message:";
    diag ($res->errorstring) if ($res->errorstring ne "connection failed(IPv6 socket failure)");
    diag ("configuring ".$AAAA_address." ". $A_address." as nameservers");
    $res->nameservers($AAAA_address,$A_address);
    undef $answer;
#	$res->print;
    $answer=$res->send("net-dns.org","NS","IN");
    is (($answer->answer)[0]->type, "NS","Fallback to V4 succeeded");
    
    
}




#
#
#  Now test AXFR functionality.
#
#
my $socket;
SKIP: { skip "online tests are not enabled", 2 unless  (-e 't/IPv6.enabled' && ! -e 't/IPv6.disabled');

	# First use the local resolver to query for the AAAA record of a 

	$res2=Net::DNS::Resolver->new;
	# $res2->debug(1);
	my $nsanswer=$res2->send("net-dns.org","NS","IN");
	SKIP:{ skip "No answers for NS queries",2 unless $nsanswer && ( $nsanswer->header->ancount != 0 );	      
	      is (($nsanswer->answer)[0]->type, "NS","Preparing  for v6 transport, got NS records for net-dns.org");
	      my $AAAA_address;
	       
	      foreach my $ns ($nsanswer->answer){
		  next if $ns->nsdname !~ /net-dns\.org$
/; # User net-dns.org only
		  my $aaaa_answer=$res2->send($ns->nsdname,"AAAA","IN");

		  next if ($aaaa_answer->header->ancount == 0);
		  is (($aaaa_answer->answer)[0]->type,"AAAA", "Preparing  for v6 transport, got AAAA records for ". $ns->nsdname);
		  $AAAA_address=($aaaa_answer->answer)[0]->address;
		  diag ("\n\t\t Trying to connect to  ". $ns->nsdname . " ($AAAA_address)");
		  last;
	      }

	       
	       ok(1,"Dummy test: No AAAA Records found, we will skip some other tests") unless $AAAA_address;
	       

	       
	       $res2->nameservers($AAAA_address);
	       # $res2->print;
	       
	       $socket=$res2->axfr_start('example.com');
	       
	}
}



SKIP: { skip "axfr_start did not return a socket", 2 unless defined($socket);
	is(ref($socket),"IO::Socket::INET6","axfr_start returns IPv6 Socket");
	my ($rr,$err)=$res2->axfr_next;
	is($res2->errorstring,'Response code from server: NOTAUTH',"Transfer is not authorized (but our connection worked)");

}


use Net::DNS::Nameserver;
my $ns = Net::DNS::Nameserver->new(
               LocalAddr        => ['::1'  ],
               LocalPort        => "5363",
               ReplyHandler => \&reply_handler,
               Verbose          => 1
        );


ok($ns,"nameserver object created on IPv6 ::1");
