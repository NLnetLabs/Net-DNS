# $Id$
# This code is not supposed to be included into the distribution.

use Test::More;
use Net::DNS::Nameserver;
use Net::DNS::Resolver;
use strict;
use Data::Dumper;
plan tests => 3;

use vars qw(
	    $address
	    $TestPort
            $lameloop
            $tcptimeout
	    );

$lameloop  = 0;
$TestPort  = 53000 + int(rand(1000));
$address   = "127.0.0.1";

my $nameserver;

$nameserver=Net::DNS::Nameserver->new(
	LocalAddr        => $address,
	LocalPort        => $TestPort,
	ReplyHandler => \&reply_handler,
	Verbose          => 0,
	IdleTimeout      => 2,
	);


my $resolver=Net::DNS::Resolver->new(
    nameservers => [ $address ],
    port       => $TestPort,
    persistent_tcp => 1,
    debug    => 0,
    tcp_timeout => 2,
    );

# We to tickle the nameserver for it to check the resolvers idle time
#
my $tickler=Net::DNS::Resolver->new(
    nameservers => [ $address ],
    port       => $TestPort,
    persistent_tcp => 1,
    debug    => 0,
    tcp_timeout => 2,
    );




sub reply_handler {
    my ($qname, $qclass, $qtype, $peerhost,$query,$conn) = @_;
    die "Sockhost failure" if ($conn->{"sockhost"} ne "127.0.0.1");
    die "Sockport failure" if ($conn->{"sockport"} ne $TestPort);
    return ("NXDOMAIN");
}

my $pid;
 FORK: {
     no strict 'subs';  # EAGAIN
     if ($pid=fork) {# assign result of fork to $pid,

	 sleep 1;
	 # Parent process here
	 $resolver->usevc(1);

	 diag('Nameserver has idle timeout of two seconds');
	 ok(defined($resolver->send("A.bla.foo","A")), 'First query succeeded');
	 sleep 1; $tickler->send("1.bla.foo","A");
	 ok(defined($resolver->send("B.bla.foo","A")), 'Second query succeeded after one second idle time');
	 sleep 1; $tickler->send("2.bla.foo","A");
	 sleep 1; $tickler->send("3.bla.foo","A");
	 sleep 1; $tickler->send("4.bla.foo","A");
	 ok(! defined($resolver->send("C.bla.foo","A")), 'Third query failed after three seconds idle time');
	 kill 1, $pid;

     } elsif (defined($pid)) {
	  # Child process here
	  #parent process pid is available with getppid
	  # exec will transfer control to the child process,
	  my $i = 0;

	  while ($i < 10) {
		  $nameserver->loop_once(10);
		  $i += 1;
	  }

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



