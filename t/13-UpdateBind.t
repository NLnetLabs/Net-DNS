# $Id$		 -*-perl-*- 

#
#  These tests are called only if Net::DNS::TestNS is available
#

# You should have a couple of IP addresses at your disposal
#  sudo ifconfig lo0 inet 127.53.53.1 netmask 255.255.255.255 alias
#  sudo ifconfig lo0 inet 127.53.53.2 netmask 255.255.255.255 alias
#  sudo ifconfig lo0 inet 127.53.53.3 netmask 255.255.255.255 alias
# ...
#  sudo ifconfig lo0 inet 127.53.53.11 netmask 255.255.255.255 alias




use Test::More;
use strict;
my $debug=0;
use Net::DNS;
use Net::DNS::Update;
use Data::Dumper;
use t::TestData;

use vars qw(
	    @Addresses
	    $TestPort
            $numberoftests
            $tcptimeout
            $named
	    );



 

sub runtests {
    # Send the update to the zone's primary master. (should be consistent with named.conf fragment below)
    my $res = Net::DNS::Resolver->new;
    $res->nameservers('127.53.53.8');
    $res->port('5334');
    sleep (1);

    # @rrs is exported from t::TestData
    foreach my $data (@rrs) {
	$data->{'name'}="foo.example.com";
	$data->{'ttl'}=10;
	
	my $RR=Net::DNS::RR->new(
	    %{$data});
#	$data->{'name'}="example.com" if ($data->{'type'} eq 'SOA');
	my $update = Net::DNS::Update->new('example.com');
	# Prerequisite is that no type records exist for the name.
	$update->push(pre => nxrrset($data->{'name'}."  ".$data->{'type'}));
      	$update->push(update => rr_add($RR->string));
	my $reply = $res->send($update);
	# Did it work?
	select(undef, undef, undef, 0.2);
	SKIP: {
	    skip 'Update failed: '.$res->errorstring, 1 unless $reply ;
	    
	    is ($reply->header->rcode, 'NOERROR', "Update succeeded for ".$data->{'type'}) ||
	    		diag ('Update failed: ', $reply->header->rcode)
	}
	
	my $query=Net::DNS::Packet->new($data->{'name'},$data->{'type'});
	undef($reply);
	$reply=$res->send($query);
	#$reply->print;
	my $ans=($reply->answer)[0];
      SKIP: {
	  skip "no answer returned ".$reply->header->rcode, 1 unless defined ($ans);
	  is( $ans->string,$RR->string,"In and out match ". $data->{'type'});
	}


	unless ($data->{type} eq "A" ||
		$data->{type} eq "SOA" 

	    ){
	    #Delete them records again
	    
	    undef($update);
	    $update = Net::DNS::Update->new('example.com');

	    $update->push(pre    => yxrrset($data->{'name'}.' '.$data->{'type'}));
	    $update->push(update => rr_del($data->{'name'}.' '.$data->{'type'}));
	    undef ($reply);
	    $reply = $res->send($update);
	    # Did it work?
	  SKIP: {
	      skip 'Update failed: '.$res->errorstring, 1 unless $reply ;
	      
	      is ($reply->header->rcode, 'NOERROR', "Delete succeeded for ".$data->{'type'}) ||
		  diag ('Update failed: ', $reply->header->rcode)
	    }
	    
	}
    }

}





BEGIN {
    $named="/usr/local/sbin/named";
    $tcptimeout=6;
    $TestPort  = 5334;
    @Addresses = qw (
		     127.53.53.8
		     );

    $numberoftests=2*@rrs-2;
    
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

	if ( ! -x $named ) {
	  diag ("You will need to have named installed at  ". $named);
	  exit;
	}
	plan tests => $numberoftests;
    }else{

       plan skip_all => 'Some modules required for this test are not available (dont\'t worry about this)';          
       exit;
   }

}	

open(NAMEDCONF, ">t/named.conf") || die "could not open t/named.conf";



print NAMEDCONF <<ENDCONF;
options {
   listen-on port 5334 { 127.53.53.8; };
   pid-file "t/named-pid";
};



zone "example.com" IN {
  type master;
  file "t/example.com";
  allow-update { localhost; };
};



ENDCONF

open(ZONEFILE,">t/example.com") || die "could not open t/example.com";

print ZONEFILE <<ENDZONE;
;;; TESTZONE fot 12-TestUpdate.t
example.com.   	60 IN	SOA ns.example.com. olaf.cpan.org. (
				2400002975 ; serial
				450        ; refresh (7 minutes 30 seconds)
				30         ; retry (30 seconds)
				345600     ; expire (4 days)
				600        ; minimum (10 minutes)
				)



example.com. 60 IN NS ns.example.com.
ns.example.com.  60 IN A 127.53.53.8

mx-exchange.example.com.  60 IN A 127.53.53.8


ENDZONE

my $pid;


die "Can't fork: $!" unless defined($pid = fork);
if ($pid) {           # parent
    sleep 2;
    runtests();
    print "PId $pid\n";
    kill 2, $pid;

} else {
    # Consider sanitizing the environment even more.
    exec $named, '-f', '-c', 't/named.conf'
                or die "can't exec myprog: $!";
}


unlink("t/named.conf");
unlink("t/named-pid");
unlink("t/example.com");
unlink("t/example.com.jnl");
