
# $Id$		 -*-perl-*-



# You should have a couple of IP addresses at your disposal
#  sudo ifconfig lo0 inet 127.53.53.1 netmask 255.255.255.255 alias
#  sudo ifconfig lo0 inet 127.53.53.2 netmask 255.255.255.255 alias
#  sudo ifconfig lo0 inet 127.53.53.3 netmask 255.255.255.255 alias
# ...
#  sudo ifconfig lo0 inet 127.53.53.11 netmask 255.255.255.255 alias



# Tests bgquery and TCP socket states...
# This code is not supposed to be included into the distribution.


use Test::More;
use Net::DNS::Nameserver;
use Net::DNS::Resolver;
use strict;
use Data::Dumper;
plan tests => 15;

use vars qw(
	    @Addresses
	    $TestPort
            $lameloop
            $tcptimeout
	    );




BEGIN {
    $lameloop=0;
    $TestPort  = 53452;
    @Addresses = qw (
		     127.53.53.1
		     127.53.53.2
		     127.53.53.3
		     127.53.53.4
		     127.53.53.5
		     127.53.53.6
		     127.53.53.7
		     127.53.53.8
		     127.53.53.9
		     127.53.53.10
		     127.53.53.11
		     127.53.53.12
		     );
    
    if(
	eval {require IO::Socket;}
	){
	#Try binding to the test addresses .. 
	foreach my $address (@Addresses){
	    diag ("Testing availability of $address");
	    my $s = IO::Socket::INET->new(Proto => 'udp',
					  LocalAddr => $address,
					  LocalPort => $TestPort
		);
	    
	    
	    
	    unless ($s){
		diag ("This test needs ".join (" ",@Addresses). " to be configured on your system");
		
		plan skip_all =>  "$address has not been configured";
		exit;
	    }
	    close ($s);
	    
	    
	}
    }else{
	
	plan skip_all => 'Some prerequisites required for this test are not available (dont\'t worry about this)';          
	exit;
    }
    
}

my @nameserver;
my $i=0;

foreach my $address (@Addresses){    
    $nameserver[$i]=Net::DNS::Nameserver->new(
	LocalAddr        => $address,
	LocalPort        => $TestPort,
	ReplyHandler => \&reply_handler,
	Verbose          => 0,
	);
    $i++;
}



my $resolver=Net::DNS::Resolver->new(
    nameservers => ["127.53.53.1"],
    port       => $TestPort,
    debug    => 0,
    );



sub reply_handler {
    my ($qname, $qclass, $qtype, $peerhost) = @_;
#    print "QNAME: $qname QTYPE: $qtype\n";
    # mark the answer as authoritive (by setting the 'aa' flag
    return ("SERVFAIL");
}



#
# For each nameserver fork-off seperate process
#
#
	
my @pid;
my $j=0;
while ($j<@Addresses){
  FORK: {
      no strict 'subs';  # EAGAIN
      if ($pid[$j]=fork) {# assign result of fork to $pid,
	  # Parent process here
	  
      } elsif (defined($pid[$j])) {
	  # Child process here
	  #parent process pid is available with getppid
	  # exec will transfer control to the child process,
	  #Verbose level is set during construction.. The verbose method
	  # may have been called afterward.
	  $nameserver[$j]->loop_once(60);
	  while( $nameserver[$j]->get_open_tcp() ){
	      $nameserver[$j]->loop_once(1);
	  }
	  exit();
      } elsif ($! == EAGAIN) {
	  # EAGAIN is the supposedly recoverable fork error
	  sleep 5;
	  redo FORK;
      }else {
	  #weird fork error
	  die "Can't fork: $!\n";
      }
    }
    $j++;
}

is( @pid, @Addresses,"Sufficient forks");


$j=0;
foreach my $address (@Addresses){
    $resolver->nameservers($address);
    $resolver->usevc(1) if ($j>6);
    $resolver->persistent_tcp(1) if ($j>7);
    $resolver->persistent_udp(1) if ($j>3);
    $j++;

    if ($j%2){
	my $socket=$resolver->bgsend("example.com") || die $resolver->errorstring;
	until ($resolver->bgisready($socket)) {
	    sleep(1);
	    # do some other processing
	}
	my $packet = $resolver->bgread($socket);	 
	$socket = undef;
	is($packet->header->rcode,"SERVFAIL","Servail returned from $address");
    }else{
	my $packet = $resolver->send("example.com") || die  $resolver->errorstring;
	is($packet->header->rcode,"SERVFAIL","Servail returned from $address");

    }
}


use IO::Socket;

is(keys %{$resolver->{'sockets'}[AF_UNSPEC]},2,"propper amount of persistent TCP");
is(keys %{$resolver->{'sockets'}[AF_INET]},1,"propper amount of persistent UDP");


