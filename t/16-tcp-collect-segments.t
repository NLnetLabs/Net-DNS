# $Id$
# This code is not supposed to be included into the distribution.

use Test::More;
use Net::DNS::Nameserver;
use Net::DNS::Packet;
use strict;

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


sub reply_handler {
    my ($qname, $qclass, $qtype, $peerhost,$query,$conn) = @_;
    # Sockhost might be different on jailed environments
    # die "Sockhost failure" if ($conn->{"sockhost"} ne "127.0.0.1");
    die "Sockport failure" if ($conn->{"sockport"} ne $TestPort);
    return ("NXDOMAIN");
}

my $pid;
 FORK: {
     no strict 'subs';  # EAGAIN
     if ($pid=fork) {# assign result of fork to $pid,

	 sleep 1;
	 # Parent process here

	 my $packet = Net::DNS::Packet->new("A.bla.foo", "A");
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
	 	$packet = Net::DNS::Packet->new(\$buf);

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

	  # The packet it 27 bytes long and will thus be sent in three parts.
	  # Because the first might take up two calls to loop_once, we need
	  # four calls.
	  #
	  while ($i < 4) {
		  $nameserver->loop_once(2);
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



