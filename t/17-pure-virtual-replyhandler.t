# $Id$
# This code is not supposed to be included into the distribution.

use Test::More;
use Net::DNS::Nameserver;
use Net::DNS::Resolver;
use strict;

plan tests => 6;

use vars qw(
	    $address
	    $TestPort1
	    $TestPort2
	    $TestPort3
	    $TestPort4
            $lameloop
	    );

$TestPort1 = 53000 + int(rand(250));
$TestPort2 = 53250 + int(rand(250));
$TestPort3 = 53500 + int(rand(250));
$TestPort4 = 53750 + int(rand(250));
$address   = "127.0.0.1";

package MyNameserver;

@MyNameserver::ISA = ("Net::DNS::Nameserver");

sub MyName { return "MyNameserver"; }

sub ReplyHandler {
	my ($self, $qname, $qclass, $qtype, $peerhost,$query,$conn) = @_;
	my ($rcode, @ans, @auth, @add);
	my $myname = $self->MyName;
	push @ans, Net::DNS::RR->new(qq($qname 3600 $qclass $qtype "$myname"));
	return ("NOERROR", \@ans, \@auth, \@add, { aa => 1});
}

package AnotherNameserver;

@AnotherNameserver::ISA = ("MyNameserver");

sub MyName { return "AnotherNameserver"; }

package YetAnotherNameserver;

@YetAnotherNameserver::ISA = ("AnotherNameserver");

sub MyName { return "YetAnotherNameserver"; }

sub ReplyHandler {
	my ($self, $qname, $qclass, $qtype, $peerhost,$query,$conn) = @_;
	my ($rcode, @ans, @auth, @add);
	my $myname = $self->MyName;
	push @ans, Net::DNS::RR->new(qq($qname 3600 $qclass $qtype "$myname"));
	return ("NOERROR", \@ans, \@auth, \@add, { aa => 1});
}

package NoReplyHanlderNameserver;

@NoReplyHandlerNameserver::ISA = ("Net::DNS::Nameserver");

package main;

{ 
	my $warning;
	local $SIG{__WARN__} = sub { $warning = (split /\n/, $_[0])[0]; };
	my $nameserver = NoReplyHandlerNameserver->new(
		LocalAddr => $address, 
		LocalPort => $TestPort1
		); 
	is($nameserver, undef, "ReplyHandler is required: $warning");
};

sub MyReplyHandler {
	my ($qname, $qclass, $qtype, $peerhost,$query,$conn) = @_;
	my ($rcode, @ans, @auth, @add);
	push @ans, Net::DNS::RR->new(qq($qname 3600 $qclass $qtype "MyReplyHandler"));
	return ("NOERROR", \@ans, \@auth, \@add, { aa => 1});
}

my $nameserver = NoReplyHandlerNameserver->new(
	LocalAddr => $address, 
	LocalPort => $TestPort1,
	ReplyHandler => \&MyReplyHandler,
	);
isnt($nameserver, undef, "ReplyHandler as parameter makes nameserver");

my @nameservers = (
	$nameserver,
	MyNameserver->new(
		LocalAddr  => $address,
		LocalPort  => $TestPort2,
		),
	AnotherNameserver->new(
		LocalAddr  => $address,
		LocalPort  => $TestPort3,
		),
	YetAnotherNameserver->new(
		LocalAddr  => $address,
		LocalPort  => $TestPort4,
		),
	);


my $pid;
my @pids;
foreach my $nameserver (@nameservers) {
    FORK: {
	 no strict 'subs';  # EAGAIN
	 if ($pid=fork) {# assign result of fork to $pid,

	     # Parent process here
	    push @pids, $pid;

	 } elsif (defined($pid)) {
	      $nameserver->loop_once(3);
	      $nameserver->loop_once(3);
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
}


my $resolver = Net::DNS::Resolver->new(
	nameservers => ["127.0.0.1"],
	port        => $TestPort1,
	debug       => 0
	);
$resolver->usevc(1);
sleep 1;

my $answer = $resolver->query("example.", "TXT"); 
is($answer && $answer->answer > 0 && ($answer->answer)[0]->string, q(example.	3600	IN	TXT	"MyReplyHandler"), "ReplyHandler as parameter");

$resolver->port($TestPort2);
$answer = $resolver->query("example.", "TXT"); 
is($answer && $answer->answer > 0 && ($answer->answer)[0]->string, q(example.	3600	IN	TXT	"MyNameserver"), "ReplyHandler as method");

$resolver->port($TestPort3);
$answer = $resolver->query("example.", "TXT"); 
is($answer && $answer->answer > 0 && ($answer->answer)[0]->string, q(example.	3600	IN	TXT	"AnotherNameserver"), "ReplyHandler as method in the super class");

$resolver->port($TestPort4);
$answer = $resolver->query("example.", "TXT"); 
is($answer && $answer->answer > 0 && ($answer->answer)[0]->string, q(example.	3600	IN	TXT	"YetAnotherNameserver"), "Overloaded ReplyHandler");

foreach $pid (@pids) {
	kill 1, $pid;
}

