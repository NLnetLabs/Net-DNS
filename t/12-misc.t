
# $Id: 11-escapedchars.t 319 2005-05-30 17:12:09Z olaf $		 -*-perl-*-



# You should have a couple of IP addresses at your disposal
#  sudo ifconfig lo0 inet 127.53.53.1 netmask 255.255.255.255 alias
#  sudo ifconfig lo0 inet 127.53.53.2 netmask 255.255.255.255 alias
#  sudo ifconfig lo0 inet 127.53.53.3 netmask 255.255.255.255 alias
# ...
#  sudo ifconfig lo0 inet 127.53.53.11 netmask 255.255.255.255 alias




use Test::More;
use Net::DNS::Nameserver;
use Net::DNS::Resolver;
use strict;

plan tests => 1;

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

my $nameserver=Net::DNS::Nameserver->new(
    LocalAddr        => "127.53.53.11",
    LocalPort        => $TestPort,
    ReplyHandler => \&reply_handler,
    Verbose          => 0,
    );

my $resolver=Net::DNS::Resolver->new(
    nameservers => ["127.53.53.11"],
    port       => $TestPort,
    debug    => 0,
    );



sub reply_handler {
    my ($qname, $qclass, $qtype, $peerhost) = @_;
    print "QNAME: $qname QTYPE: $qtype\n";
    # mark the answer as authoritive (by setting the 'aa' flag
    return ("SERVFAIL");
}


	
my $pid;

 FORK: {
     no strict 'subs';  # EAGAIN
     if ($pid=fork) {# assign result of fork to $pid,
	 # see if it is non-zero.
	 # Parent process here
	 # Child pid is in $pid
	 my $socket=$resolver->bgsend("example.com") || die " $resolver->errorstring";
	 until ($resolver->bgisready($socket)) {
	     # do some other processing
	 }
	 my $packet = $resolver->bgread($socket);	 
	 $socket = undef;
	 is($packet->header->rcode,"SERVFAIL","Servail returned");
     } elsif (defined($pid)) {
	 # Child process here
	 #parent process pid is available with getppid
	 # exec will transfer control to the child process,
	 #Verbose level is set during construction.. The verbose method
	 # may have been called afterward.
	 $nameserver->loop_once(10);
     } elsif ($! == EAGAIN) {
	 # EAGAIN is the supposedly recoverable fork error
	 sleep 5;
	 redo FORK;
     }else {
	 #weird fork error
	 die "Can't fork: $!\n";
     }
}

kill $pid;










