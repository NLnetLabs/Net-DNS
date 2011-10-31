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

$address   = "127.0.0.1";
sub freeport {
    my @sockets = map { IO::Socket::INET->new(Listen => 1) } (1..shift);
    return map { $_->sockport } @sockets;
}
my ($TestPort1, $TestPort2, $TestPort3, $TestPort4) = freeport(4);

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

sub MyReplyHandler {
	my ($qname, $qclass, $qtype, $peerhost,$query,$conn) = @_;
	my ($rcode, @ans, @auth, @add);
	push @ans, Net::DNS::RR->new(qq($qname 3600 $qclass $qtype "MyReplyHandler"));
	return ("NOERROR", \@ans, \@auth, \@add, { aa => 1});
}

sub serve {
    my $nameserver = shift;

    no strict 'subs'; # EAGAIN

    FORK: {
        if (! (my $pid = fork)) {
            if (defined $pid) {
                $nameserver->loop_once(3);
                $nameserver->loop_once(1);
                exit(0);
            } elsif ($! == EAGAIN) {
                # EAGAIN is the supposedly recoverable fork error
                sleep 5;
                redo FORK;                
            } else {
                # weird fork error
                die "Can't fork: $!\n";
            }
        }
    }
}


# -- test 1 -------------------------------------------------------------------

{ 
	my $warning;
	local $SIG{__WARN__} = sub { $warning = (split /\n/, $_[0])[0]; };
	my $nameserver = NoReplyHandlerNameserver->new(
		LocalAddr => $address, 
		LocalPort => $TestPort1
		); 
	is($nameserver, undef, "ReplyHandler is required: $warning");
};

# -- test 2 -------------------------------------------------------------------

my $nameserver = NoReplyHandlerNameserver->new(
	LocalAddr => $address, 
	LocalPort => $TestPort1,
	ReplyHandler => \&MyReplyHandler,
	);
isnt($nameserver, undef, "ReplyHandler as parameter makes nameserver");

# -- test 3 -------------------------------------------------------------------

# Nameservers will be forked one by one, because forking all nameservers at 
# once does not work too well on windows.

serve($nameserver);

my $resolver = Net::DNS::Resolver->new(
	nameservers => ["127.0.0.1"],
	port        => $TestPort1,
	debug       => 0
	);
$resolver->usevc(1);
sleep 1;

my $answer = $resolver->query("example.", "TXT"); 
is($answer && $answer->answer > 0 && ($answer->answer)[0]->string, q(example.	3600	IN	TXT	"MyReplyHandler"), "ReplyHandler as parameter");

wait;

# -- test 4 -------------------------------------------------------------------

serve(MyNameserver->new(
	LocalAddr  => $address,
	LocalPort  => $TestPort2,
	));

$resolver->port($TestPort2);
sleep 1;

$answer = $resolver->query("example.", "TXT"); 
is($answer && $answer->answer > 0 && ($answer->answer)[0]->string, q(example.	3600	IN	TXT	"MyNameserver"), "ReplyHandler as method");

wait;

# -- test 5 -------------------------------------------------------------------

serve(AnotherNameserver->new(
	LocalAddr  => $address,
	LocalPort  => $TestPort3,
	));

$resolver->port($TestPort3);
sleep 1;

$answer = $resolver->query("example.", "TXT"); 
is($answer && $answer->answer > 0 && ($answer->answer)[0]->string, q(example.	3600	IN	TXT	"AnotherNameserver"), "ReplyHandler as method in the super class");

wait;

# -- test 6 -------------------------------------------------------------------

serve(YetAnotherNameserver->new(
	LocalAddr  => $address,
	LocalPort  => $TestPort4,
	));

$resolver->port($TestPort4);
sleep 1;

$answer = $resolver->query("example.", "TXT"); 
is($answer && $answer->answer > 0 && ($answer->answer)[0]->string, q(example.	3600	IN	TXT	"YetAnotherNameserver"), "Overloaded ReplyHandler");


