
# $Id$		 -*-perl-*-



# You should have a couple of IP addresses at your disposal
#  sudo ifconfig lo0 inet 127.53.53.12 netmask 255.255.255.255 alias

# This code is not supposed to be included into the distribution.


use Test::More;
use Net::DNS::Nameserver;
use Net::DNS::Resolver;
use strict;
use Data::Dumper;
plan tests => 2;

use vars qw(
	    $address
	    $TestPort
            $lameloop
            $tcptimeout
	    );




BEGIN {
    $lameloop=0;
    $TestPort  = 53000 + int(rand(1000));
    $address = "127.53.53.12";

    
    if(
	eval {require IO::Socket;}
	){
	#Try binding to the test addresses .. 
	diag ("Testing availability of $address:$TestPort");
	my $s = IO::Socket::INET->new(Proto => 'udp',
				      LocalAddr => $address,
				      LocalPort => $TestPort,
				      ReusePort => 1,
				      # turns out that closing the
				      # socket does not immediatly
				      # make the port available.
	    );
	
	
	
	unless ($s){
	    diag ("This test needs ".join (" ",$address). " to be configured on your system");
	    
	    plan skip_all =>  "$address has not been configured";
	    exit;
	}
	close ($s);

    }else{
	
	plan skip_all => 'Some prerequisites required for this test are not available (dont\'t worry about this)';          
	exit;
    }
    
}

my $nameserver;

$nameserver=Net::DNS::Nameserver->new(
	LocalAddr        => $address,
	LocalPort        => $TestPort,
	ReplyHandler => \&reply_handler,
	Verbose          => 0,
	);



my $resolver=Net::DNS::Resolver->new(
    nameservers => [ $address ],
    port       => $TestPort,
    persistent_tcp => 1,
    debug    => 1,
    tcp_timeout => 2,
    );



sub reply_handler {
    my ($qname, $qclass, $qtype, $peerhost) = @_;
#    print "QNAME: $qname QTYPE: $qtype\n";
    # mark the answer as authoritive (by setting the 'aa' flag
    return ("NXDOMAIN");
}



#
# For each nameserver fork-off seperate process
#
#
	
my $pid;
 FORK: {
     no strict 'subs';  # EAGAIN
     if ($pid=fork) {# assign result of fork to $pid,

	 # Parent process here
	 $resolver->usevc(1);

	 $resolver->send("bla.foo","A");
	 $resolver->send("bla.foo","A");

	 is("unknown error or no error",$resolver->errorstring,"read_tcp failed after connection reset");


	 $resolver->send("bla.foo","A");
	 is("timeout",$resolver->errorstring,"timout received");



     } elsif (defined($pid)) {
	  # Child process here
	  #parent process pid is available with getppid
	  # exec will transfer control to the child process,
	  $nameserver->loop_once(60);
	  $nameserver->loop_once(10);
	  exit;

      } elsif ($! == EAGAIN) {
	  # EAGAIN is the supposedly recoverable fork error
	  sleep 5;
	  redo FORK;
      }else {
	  #weird fork error
	  die "Can't fork: $!\n";
      }
}




$resolver->nameservers($address);
