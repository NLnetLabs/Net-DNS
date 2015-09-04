# $Id$ -*-perl-*-

use strict;
use Test::More;

use Net::DNS;
use t::NonFatal;
use Socket;

my $debug = 0;

my @hints = qw(
		2001:500:2::c
		2001:7fd::1
		2001:500:3::42
		2001:503:c27::2:30
		2001:500:84::b
		2001:500:1::803f:235
		2001:500:2d::d
		2001:503:ba3e::2:30
		2001:500:2f::f
		2001:7fe::53
		2001:dc3::35
		);


exit( plan skip_all => 'Online tests disabled.' ) if -e 't/IPv6.disabled';
exit( plan skip_all => 'Online tests disabled.' ) unless -e 't/IPv6.enabled';


eval {
	my $res = new Net::DNS::Resolver( retry => 1 );
	exit plan skip_all => "No nameservers" unless $res->nameservers;

	my $reply = $res->send( ".", "NS" ) || die;

	my @ns = grep $_->type eq 'NS', $reply->answer, $reply->authority;
	exit plan skip_all => "Local nameserver broken" unless scalar @ns;

	1;
} || exit( plan skip_all => "Non-responding local nameserver" );


eval {
	my $res = new Net::DNS::Resolver( retry => 1 );
	exit plan skip_all => "No nameservers" unless $res->nameservers(@hints);

	my $reply = $res->send( ".", "NS" ) || die;

	my @ns = grep $_->type eq 'NS', $reply->answer, $reply->authority;
	exit plan skip_all => "Unexpected response from root server" unless scalar @ns;

	1;
} || exit( plan skip_all => "Unable to access global root nameservers" );


eval {
	my $res = new Net::DNS::Resolver( retry => 1 );

	my $reply = $res->send( "a.t.", "A" ) || die;

	if ( $reply->header->ancount ) {
		my $server = $reply->answerfrom;
		my ($rr) = $reply->answer;
		diag "\nFor unexplained reasons a query for 'a.t.' resolves as";
		diag $rr->string;
		diag "\nUsers of 'dig' may try 'dig a.t.' to test this hypothesis";
	}

	1;
} || exit( plan skip_all => "Unable to access local nameserver" );


plan tests => 9;


NonFatalBegin();

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
    # assume any net-dns.org nameserver will do
    my $aaaa_answer=$res->send($ns->nsdname,"AAAA","IN");
    next if ($aaaa_answer->header->ancount == 0);
    is (($aaaa_answer->answer)[0]->type,"AAAA", "Preparing  for v6 transport, got AAAA records for ". $ns->nsdname);
    $AAAA_address=($aaaa_answer->answer)[0]->address;
    $found_ns=1;
    diag ("\n\t\t Will try to connect to  ". $ns->nsdname . " ($AAAA_address)") if $debug;
    last;
}

ok(1,"Dummy test: No AAAA Records found, we will skip some other tests") unless $found_ns;

$res->nameservers($AAAA_address);
#$res->print;
$answer=$res->send("net-dns.org","SOA","IN");

is (($answer->answer)[0]->type, "SOA","Query over udp6 succeeded");



$res->usevc(1);
$res->force_v4(1);
# $res->print;
# $res->debug(1);
$answer=$res->send("net-dns.org","SOA","IN");
is ($res->errorstring,"IPv6 transport not available","Correct errorstring when forcing v4");


$res->force_v4(0);
$answer=$res->send("net-dns.org","NS","IN");
if ($answer){
    is (($answer->answer)[0]->type, "NS","Query over tcp6  succeeded");
}else{
    diag ($res->errorstring) if ($res->errorstring ne "connection failed(IPv6 socket failure)");
    diag ("configuring nameservers( $AAAA_address, $A_address )") if $debug;
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
my $iter;
SKIP: { skip "online tests are not enabled", 2 unless  (-e 't/IPv6.enabled' && ! -e 't/IPv6.disabled');

	# First use the local resolver to query for the AAAA record of a 

	$res2=Net::DNS::Resolver->new;
	# $res2->debug(1);
	my $nsanswer=$res2->send("net-dns.org","NS","IN");
	SKIP:{ skip "No answers for NS queries",2 unless $nsanswer && ( $nsanswer->header->ancount != 0 );	      
	      is (($nsanswer->answer)[0]->type, "NS","Preparing  for v6 transport, got NS records for net-dns.org");
	      my $AAAA_address;
	       
	      foreach my $ns ($nsanswer->answer){
		  my $aaaa_answer=$res2->send($ns->nsdname,"AAAA","IN");

		  next if ($aaaa_answer->header->ancount == 0);
		  is (($aaaa_answer->answer)[0]->type,"AAAA", "Preparing  for v6 transport, got AAAA records for ". $ns->nsdname);
		  $AAAA_address=($aaaa_answer->answer)[0]->address;
		  diag ("\n\t\t Trying to connect to  ". $ns->nsdname . " ($AAAA_address)") if $debug;
		  last;
	      }

	       
	       ok(1,"Dummy test: No AAAA Records found, we will skip some other tests") unless $AAAA_address;
	       

	       
	       $res2->nameservers($AAAA_address);
	       # $res2->print;
	       
	       $iter=$res2->axfr('example.com');
	       
	}
}



SKIP: { skip "axfr did not return an iterator", 2 unless defined($iter);
	is(ref($iter),"CODE","axfr returns CODE ref");
	my ($rr)=$iter->();
	is($res2->errorstring,'RCODE from server: NOTAUTH',"Transfer is not authorized (but our connection worked)");

}


NonFatalEnd();

