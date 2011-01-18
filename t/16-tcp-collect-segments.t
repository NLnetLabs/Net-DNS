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

$lameloop  = 0;
$TestPort  = 53000 + int(rand(1000));
$address   = "127.0.0.1";

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
    debug    => 0,
    tcp_timeout => 2,
    );


sub reply_handler {
    my ($qname, $qclass, $qtype, $peerhost,$query,$conn) = @_;
    die "Sockhost failure" if ($conn->{"sockhost"} ne "127.0.0.1");
    die "Sockport failure" if ($conn->{"sockport"} ne $TestPort);
#	use Data::Dumper;
#	print Dumper $conn;
#	print "QNAME: $qname QTYPE: $qtype\n";
    return ("NXDOMAIN");
}

my $pid;
 FORK: {
     no strict 'subs';  # EAGAIN
     if ($pid=fork) {# assign result of fork to $pid,

	 sleep 1;
	 # Parent process here
	 $resolver->usevc(1);

	 my $packet = $resolver->make_query_packet("A.bla.foo", "A");
	 my $data   = $packet->data;

	 my $sock = new IO::Socket::INET(
	 	PeerAddr => $address,
		PeerPort => $TestPort,
		Proto    => 'tcp'
	 );
	 my $lenmsg = pack('n', length($data));
	 $data = $lenmsg . $data;
	 while (length $data) {
		 $sock->send(substr($data, 0, 10));
		 $sock->flush();
		 substr($data, 0, 10) = '';
	 }
	 my $buf;
	 my $sel = new IO::Select($sock);
	 if (! length $sel->can_read(3)) {
	 	ok(0, 'No answer received');
	 }
	 else {
	 	$sock->recv($buf, 2);
	 	$lenmsg = unpack('n', $buf);
	 	$sock->recv($buf, $lenmsg);
	 	$packet = Net::DNS::Packet->new(\$buf, 1);

		 if (ok(defined($packet), 'We received an answer')) {
			ok($packet->header->rcode eq 'NXDOMAIN', 'Correct answer received');
		 }
	}
	kill 1, $pid;

     } elsif (defined($pid)) {
	  # Child process here
	  #parent process pid is available with getppid
	  # exit will transfer control to the child process,
	  my $i = 0;

	  while ($i < 10) {
	  	  print "Child running $i\n";
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



