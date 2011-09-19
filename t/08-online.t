# $Id$ -*-perl-*-

use Test::More;
use strict;
use Socket;
use Data::Dumper;
use t::NonFatal;

BEGIN {
	if (-e 't/online.enabled' && ! -e 't/online.disabled' ) {
		plan tests => 95;
		NonFatalBegin();
	} else {
		plan skip_all => 'Online tests disabled.';
		exit;
	}
}

BEGIN { use_ok('Net::DNS'); }

my $res = Net::DNS::Resolver->new;
#$res->debug(1);
my @rrs = (
	{
		type   		=> 'A',
		name   		=> 'a.t.net-dns.org',
		address 	=> '10.0.1.128',
	},
	{
		type		=> 'MX',
		name		=> 'mx.t.net-dns.org',
		exchange	=> 'a.t.net-dns.org',
		preference 	=> 10,
	},
	{
		type		=> 'CNAME',
		name		=> 'cname.t.net-dns.org',
		cname		=> 'a.t.net-dns.org',
	},
	{
		type		=> 'TXT',
		name		=> 'txt.t.net-dns.org',
		txtdata		=> 'Net-DNS',
	},
		
);

		

foreach my $data (@rrs) {
    
    my $packet = $res->send($data->{'name'}, $data->{'type'}, 'IN');
    
    if (ok($packet, "Got an answer for $data->{name} IN $data->{type}")) {
		is($packet->header->qdcount, 1, 'Only one question');
		if (is($packet->header->ancount, 1, 'Got single answer')) {
		
			my $question = ($packet->question)[0];
			my $answer   = ($packet->answer)[0];
			
			ok($question,                           'Got question'            );
			is($question->qname,  $data->{'name'},  'Question has right name' );
			is($question->qtype,  $data->{'type'},  'Question has right type' );
			is($question->qclass, 'IN',             'Question has right class');
			
			ok($answer,                                                       );
			is($answer->class,    'IN',             'Class correct'           );
			
			
			foreach my $meth (keys %{$data}) {
			if ($meth eq "name"){
				#names should be case insensitive
				is(lc($answer->$meth()),lc($data->{$meth}), "$meth correct ($data->{name})");
			}else{
				is($answer->$meth(), $data->{$meth}, "$meth correct ($data->{name})");
			}
		}
		}
	}
}

# Does the mx() function work.
my @mx = mx('mx2.t.net-dns.org');

my $wanted_names = [qw(a.t.net-dns.org a2.t.net-dns.org)];
my $names        = [ map { $_->exchange } @mx ];


is_deeply($names, $wanted_names, "mx() seems to be working");

# some people seem to use mx() in scalar context
is(scalar mx('mx2.t.net-dns.org'), 2,  "mx() works in scalar context");

#
# test that search() and query() DTRT with reverse lookups
#
{
    my @tests = (
	{
	    ip => '198.41.0.4',
	    host => 'a.root-servers.net',
	},
	{
	    ip => '2001:500:1::803f:235',
	    host => 'h.root-servers.net',
	},
	);
    
    foreach my $test (@tests) {
	foreach my $method (qw(search query)) {
	    my $packet = $res->$method($test->{'ip'});

	    
	  SKIP: {
	      skip "Packet returned for $method is undefined, error returned: ".$res->errorstring, 2, if !defined ($packet);
	      isa_ok($packet,  'Net::DNS::Packet');
	      
	      
	      is(lc(($packet->answer)[0]->ptrdname),lc($test->{'host'}), "$method($test->{'ip'}) works");
	    }
	}
    }
}

$res = Net::DNS::Resolver->new(
	domain     => 't.net-dns.org',
    searchlist => ['t.net-dns.org', 'net-dns.org'],
    );

my $ans_at=$res->send("a.t.", "A");
if ($ans_at->header->ancount == 1 ){
    diag "We are going to skip a bunch of checks.";
    diag "For unexplained reasons a query for 'a.t' resolves as ";
    diag "".($ans_at->answer)[0]->string ;
    diag "For users of 'dig' try 'dig a.t.' to test this hypothesis";
}
      SKIP: {
    skip "Query for a.t. resolves unexpectedly",35 if ($ans_at->header->ancount == 1 );
    
    
#$res->debug(1);
#
# test the search() and query() append the default domain and 
# searchlist correctly.
#
    {
	$res->defnames(1); $res->dnsrch(1);
	     $res->persistent_udp(0);
	     
	     my @tests = (
		 {
		     method => 'search',
		     name   => 'a',
		 },
		 {
		     method => 'search',
		     name   => 'a.t',
		 },
		 {
		     method => 'query',
		     name   => 'a',
		 },
		 
		 );
	     
	     
	     
	     foreach my $test (@tests) {
		 my $method = $test->{'method'};
		 
		 my $ans = $res->$method($test->{'name'});
		 
		 isa_ok($ans, 'Net::DNS::Packet');
		 
		 is($ans->header->ancount, 1,"Correct answer count (with $method)");
		 my ($a) = $ans->answer;
		 
		 isa_ok($a, 'Net::DNS::RR::A');
		 is(lc($a->name), 'a.t.net-dns.org',"Correct name (with $method)");
	     }

	 }
    
    
#	$res->debug(1);
    my $socket=$res->bgsend('a.t.net-dns.org','A');
    ok(ref($socket)=~/^IO::Socket::INET(6?)$/,"Socket returned");
    diag("Error condition: ".$res->errorstring ."Socket ref:".ref($socket)) unless ref($socket)=~/^IO::Socket::INET(6?)$/;
    my $loop=0;
    # burn a little CPU to get the socket ready.
    # I could off course used microsleep or something.
    while ($loop<200000){
		 $loop++;
	     }
    $loop=0;
    while ($loop<6){
	last if $res->bgisready($socket);
	sleep(1); # If burning CPU above was not sufficient.
	$loop++;
    }
    
    
    ok ($res->bgisready($socket),"Socket is ready");
  SKIP: {
      skip "No socket to read from",5 unless $res->bgisready($socket);
      $res->debug(0);
      my $ans= $res->bgread($socket);
      ok(defined($ans->answerfrom),"Answerfrom defined" .
	 (defined($ans->answerfrom)? "(".$ans->answerfrom .")":"")
	  );
      ok(defined($ans->answersize),"Answersize defined".
	 (defined($ans->answersize)? "(".$ans->answersize .")":"")
	  );
      
      undef $socket;
    SKIP: {
	skip "Answerless packet (response from ".$ans->answerfrom. " had RCODE: ".$ans->header->rcode.")", 2 unless is ($ans->header->ancount, 1,"Correct answer count");
	my ($a) = $ans->answer;
	
	isa_ok($a, 'Net::DNS::RR::A');
	is(lc($a->name), 'a.t.net-dns.org',"Correct name");
	
      }
      

    }
    
#
# test the search() and query() append the default domain and 
# searchlist correctly.
#
	$res->defnames(1); $res->dnsrch(1);
	$res->persistent_udp(1);
#	$res->debug(1);
	my @tests = (
		{
			method => 'search',
			name   => 'a',
		},
		{
			method => 'search',
			name   => 'a.t',
		},
		{
			method => 'query',
			name   => 'a',
		},
	);

	$res->send("a.t.net-dns.org A");
	
	my $sock_id= $res->{'sockets'}[AF_INET]{"UDP"};

	ok($sock_id,"Persistend UDP socket identified");

	foreach my $test (@tests) {
		my $method = $test->{'method'};

		my $ans = $res->$method($test->{'name'});
		is(  $res->{'sockets'}[AF_INET]{"UDP"},$sock_id,"Persistent socket matches");
		
		isa_ok($ans, 'Net::DNS::Packet');

		is($ans->header->ancount, 1,"Correct answer count (with persistent socket and $method)");
		
		my ($a) = $ans->answer;
		
		isa_ok($a, 'Net::DNS::RR::A');
		is(lc($a->name), 'a.t.net-dns.org',"Correct name (with persistent socket and $method)");
	}
	

	}

NonFatalEnd();
