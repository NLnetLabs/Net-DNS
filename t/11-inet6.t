# $Id: 07-misc.t,v 1.4 2002/10/15 22:13:02 ctriv Exp $ -*-perl-*-


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


SKIP: { skip "Socket6 and or IO::Socket::INET6 not loaded", 4 unless $has_inet6;
	# First test is to bind a nameserver to the ::1 port.
	# That beast should be available on every machine.

	
	# Let us bind a nameserver to ::1. First lets see if we can open a
	# socket anyhow.

	my    $tstsock = IO::Socket::INET6->new(
						Proto => 'tcp',
						LocalAddr => '::1'
					       ) 
	  or die "$! (maybe your does not have ::1)";
	
	ok ($tstsock, "IO::Socket::INET6 binds to ::1");

    }


exit unless $has_inet6; #This prevents nested SKIP blocks.. 



my $answer;
my $res;

SKIP: { skip "online tests are not enabled", 2 unless -e 't/online.enabled';

	# First use the local resolver to query for the AAAA record of a 
        # well known nameserver, than use v6 transport to get to that record.

	$res=Net::DNS::Resolver->new;
	# $res->debug(1);
	my $nsanswer=$res->send("ripe.net","NS","IN");
	is (($nsanswer->answer)[0]->type, "NS","Preparing  for v6 transport, got NS records for ripe.net");
	my $AAAA_address;
	foreach my $ns ($nsanswer->answer){
	    my $aaaa_answer=$res->send($ns->nsdname,"AAAA","IN");
	    next if ($aaaa_answer->header->ancount == 0);
	    is (($aaaa_answer->answer)[0]->type,"AAAA", "Preparing  for v6 transport, got AAAA records for ". $ns->nsdname);
	    $AAAA_address=($aaaa_answer->answer)[0]->address;
	    diag ("Using ". $ns->nsdname . " ($AAAA_address) to query for ripe.net SOA");
	    last;
	}
	    

	$res->nameservers($AAAA_address);

	$res->print;
	$answer=$res->send("ripe.net","SOA","IN");

	diag "The test below are skipped because of '" . $res->errorstring ."' while connecting\n"  if($res->errorstring =~ /Send error: /);
	diag "This could be a indication that you actually do not have IPv6 connectivity"  if($res->errorstring =~ /Send error: /);
	diag "Please try if 'ping6 ".$AAAA_address."' works before contacting the author"   if($res->errorstring =~ /Send error: /);
	
    }
 SKIP: { skip "No answer available to analise", 2 unless $answer;
	 
	 $answer->print;
	 is (($answer->answer)[0]->type, "SOA","Query over udp6 succeeded");
	 $res->usevc(1);
	 $answer=$res->send("ripe.net","NS","IN");
	 is (($answer->answer)[0]->type, "NS","Query over tcp6  succeeded");
	 
	 
     }





