# $Id$ -*-perl-*-


my $has_inet6;
use Test::More tests=>6;
use strict;


BEGIN { use_ok('Net::DNS');

	if ( eval {require Socket6;} &&
		 # INET6 older than 2.01 will not work; sorry.
		 eval {require IO::Socket::INET6; IO::Socket::INET6->VERSION("2.01");}) {
	    import Socket6;
	    $has_inet6=1;
	}else{
	    $has_inet6=0;
	}
       
      }


SKIP: { skip "Socket6 and or IO::Socket::INET6 not loaded", 5 unless $has_inet6;

	diag "";
	diag "The libraries needed for IPv6 support have been found\n";
	diag "\t\tNow we establish if  we can bind to ::1";

	# First test is to bind a nameserver to the ::1 port.
	# That beast should be available on every machine.

	
	# Let us bind a nameserver to ::1. First lets see if we can open a
	# socket anyhow.

	my    $tstsock = IO::Socket::INET6->new(
						Proto => 'tcp',
						LocalAddr => '::1'
					       ) 

	    or 	diag "\n\n\t\tFailed to bind to ::1\n\t\t$!\n\n".
	    "\t\tWe assume there is no IPv6 connectivity and skip the tests\n\n";
	    ;
	    

    }


exit unless $has_inet6; #This prevents nested SKIP blocks.. 



my $answer;
my $res;

SKIP: { skip "online tests are not enabled", 2 unless -e 't/online.enabled';

	# First use the local resolver to query for the AAAA record of a 
        # well known nameserver, than use v6 transport to get to that record.
	diag "";
	diag "";
	diag "\tTesting for global IPv6 connectivity...\n";
	diag "\t\t preparing...";
	$res=Net::DNS::Resolver->new;
	# $res->debug(1);
	my $nsanswer=$res->send("ripe.net","NS","IN");
	is (($nsanswer->answer)[0]->type, "NS","Preparing  for v6 transport, got NS records for ripe.net");
	my $AAAA_address;
	foreach my $ns ($nsanswer->answer){
	    next if $ns->nsdname !~ /ripe\.net/; # User rupe.net only
	    my $aaaa_answer=$res->send($ns->nsdname,"AAAA","IN");
	    next if ($aaaa_answer->header->ancount == 0);
	    is (($aaaa_answer->answer)[0]->type,"AAAA", "Preparing  for v6 transport, got AAAA records for ". $ns->nsdname);
	    $AAAA_address=($aaaa_answer->answer)[0]->address;


	    diag ("\n\t\t Trying to connect to  ". $ns->nsdname . " ($AAAA_address)");
	    last;
	}
	    

	$res->nameservers($AAAA_address);

	$res->print;
	$answer=$res->send("ripe.net","SOA","IN");
	if($res->errorstring =~ /Send error: /){	
		diag "\n\t\t Connection failed: " . $res->errorstring ;
		diag "\n\t\t It seems you do not have global IPv6 connectivity' \n" ;
		diag "\t\t This is not an error in Net::DNS \n";

		diag "\t\t You can confirm this by trying 'ping6 ".$AAAA_address."' \n\n";
	}		
	
    }
 SKIP: { skip "No answer available to analyse", 3 unless $answer;
	 
	 $answer->print;
	 is (($answer->answer)[0]->type, "SOA","Query over udp6 succeeded");
	 $res->usevc(1);
	 $answer=$res->send("ripe.net","NS","IN");
	 is (($answer->answer)[0]->type, "NS","Query over tcp6  succeeded");
	 $res->force_v4(1);
	 $res->print;
	 $res->debug(1);
	 $answer=$res->send("ripe.net","SOA","IN");
	 is ($res->errorstring,"no nameservers","Correct errorstring when forcing v4");
	 
     }





