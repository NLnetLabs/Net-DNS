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
            $namedcheckzone
	    );


sub buildzonefile {
    # Send the update to the zone's primary master. (should be consistent with named.conf fragment below)
    open (ZONEFILE, "> t/example.com") || die "could not open t/zonefile";
    # @rrs is exported from t::TestData

    print ZONEFILE ";;; TEST ZONE FILE created by t-UpdateBind.t\n";
    
    print ZONEFILE "\$TTL 10\n";

    foreach my $data (@rrs) {
	# pause a moment
	select(undef, undef, undef, 0.1);
	
	$data->{'name'}="bla.example.com.";
	# special casing for SOA, that must be zone-apex
	$data->{'name'}="example.com" if ($data->{'type'} eq 'SOA');
	
	# special casing for CNAME, may not have any data at the name
	# foo.example.com has A and AAAA rrs
	$data->{'name'}="alias-1.example.com" if ($data->{'type'} eq 'CNAME');
	
	# special casing for NS, may not have any data at the name
	$data->{'name'}="zonecut-1.example.com" if ($data->{'type'} eq 'NS');




	$data->{'ttl'}=10;
	my $RR=Net::DNS::RR->new(
	    %{$data});

	print ZONEFILE $RR->string ."\n";

    }

    print ZONEFILE <<ZONEDATA;


example.com.              IN      NS    ns.example.com.
ns.example.com.           IN       A    127.53.53.8


mx-exchange.example.com.  IN       A    127.53.53.8

ZONEDATA


 
}
 

sub runtests {
    # Send the update to the zone's primary master. (should be consistent with named.conf fragment below)
    my $res = Net::DNS::Resolver->new;
    $res->nameservers('127.53.53.8');
    $res->port('5334');
    sleep (1);

    # @rrs is exported from t::TestData
    foreach my $data (@rrs) {
	# pause a moment
	select(undef, undef, undef, 0.1);

	$data->{'name'}="foo.example.com.";
	# special casing for SOA, that must be zone-apex
	$data->{'name'}="example.com" if ($data->{'type'} eq 'SOA');

	# special casing for CNAME, may not have any data at the name
	# foo.example.com has A and AAAA rrs
	$data->{'name'}="alias-2.example.com" if ($data->{'type'} eq 'CNAME');

	# special casing for NS, may not have any data at the name
	$data->{'name'}="zonecut-2.example.com" if ($data->{'type'} eq 'NS');




	$data->{'ttl'}=10;
	my $RR=Net::DNS::RR->new(
	    %{$data});


	my $update = Net::DNS::Update->new('example.com');
	# Prerequisite is that no type records exist for the name. Again for some
	# RRs we need special casing
	unless ($data->{'type'} eq "SOA" ){
	    $update->push(pre => nxrrset($data->{'name'}."  ".$data->{'type'}));
	}else{
	    $update->push(pre => yxrrset($data->{'name'}."  ".$data->{'type'}));
	}
	$update->push(update => rr_add($RR->string));

	my $reply = $res->send($update);
	# Did it work?
	my $updatesuccess=0;
	SKIP: {
	    skip 'Update failed: '.$res->errorstring, 1 unless $reply ;

	    
	    $updatesuccess= is ($reply->header->rcode, 'NOERROR', "Update succeeded for ".$data->{'type'}) ;
	    diag ('Update failed: ', $reply->header->rcode, " for: ".$RR->string) unless $updatesuccess;
	    
		
	}


	my $query=Net::DNS::Packet->new($data->{'name'},$data->{'type'});
	undef($reply);
	$reply=$res->send($query);
	#$reply->print;
	my $ans=($reply->answer)[0];
	#special case for NS: delegation
	$ans=($reply->authority)[0] if $data->{'type'} eq "NS";  
      SKIP:{
	  skip "no answer returned ". ($updatesuccess?"errorcode: ":" after failed update: ").$reply->header->rcode, 1 unless defined ($ans) && $updatesuccess ;
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
	      skip  $updatesuccess?'Update failed: '.$res->errorstring:"Delete cannot succeed after a failed update" , 2 unless $reply && $updatesuccess ;
	      
	      is ($reply->header->rcode, 'NOERROR', "Delete succeeded for ".$data->{'type'}) ||
		  diag ('Update failed: ', $reply->header->rcode);
		  
		  undef($reply);
	      $reply=$res->send($query);
	      ok(! $reply->answer, "empty answer section for ".
		 $data->{'name'}.' '.$data->{'type'}. " after rr_del");


	    }



	    
	    
	}
	
	# Query the data as loaded from the zonefile
	undef($query);
	undef($reply);
	$data->{'name'} =~ s/foo/bla/;
	$data->{'name'} =~ s/-2/-1/;
	# CHEATING by modifying attributes
	$RR->{'name'} =~ s/foo/bla/;
	$RR->{'name'} =~ s/-2/-1/;
	$query=Net::DNS::Packet->new($data->{'name'},$data->{'type'});
	$reply=$res->send($query);

      SKIP:{
	  skip "no answer returned ". ($updatesuccess?"errorcode: ":"after failed update: ").$reply->header->rcode, 2 unless defined ($ans) && $updatesuccess ;
	  
	  
	  #$reply->print;
	  if ($data->{'type'} eq "IPSECKEY") {
	      #special casing for IPSEC KEY
	      ok ( $reply->answer == 4 , "Answer for IPSECKEY contains 4 RR");
	      my $i=0;
	      while ($i < $reply->answer){
		  my $ans=($reply->answer)[$i];
		  $i++;
		  next unless $ans->string eq $RR->string;
		  is( $ans->string,$RR->string,"query from authoritative zone match ". $data->{'type'});
		  last;
	      }
	      
	      
  	  }else{
	      
	      my $ans;
	      if ($data->{'type'} eq "NS"){
		  #special case for NS: delegation
		  $ans=($reply->authority)[0] 
	      }else{
		  # Other query types have their answer as first (an only) RR in the answer section
		  ok ( $reply->answer == 1 , "Answer contains 1 RR for $data->{'name'} $data->{'type'}");
		  $ans=($reply->answer)[0];
	  }
	      
	      is( $ans->string,$RR->string,"query from authoritative zone match ". $data->{'type'});
	      
	      
	  }	  
	}
    }
    
}
    




BEGIN {
    $named="/usr/local/sbin/named";
    $namedcheckzone="/usr/local/sbin/named-checkzone";
    $tcptimeout=6;
    $TestPort  = 5334;
    @Addresses = qw (
		     127.53.53.8
		     );

    $numberoftests=6*@rrs-5;
    
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




buildzonefile();
ok(   ! system("$namedcheckzone example.com t/example.com"), "Checking zone loading");
open(NAMEDCONF, ">t/named.conf") || die "could not open t/named.conf";



print NAMEDCONF <<ENDCONF;
options {
   listen-on port 5334 { 127.53.53.8; };
   pid-file "t/named-pid";
   recursion no;

};



zone "example.com" IN {
  type master;
  file "t/example.com";
  allow-update { 127/8; };
};



ENDCONF


my $pid;


die "Can't fork: $!" unless defined($pid = fork);
if ($pid) {           # parent
    select(undef, undef, undef, 0.5);
    runtests();
#   sleep 60;
    kill 2, $pid;

} else {
    unlink("t/example.com.jnl") if -f "t/example.com.jnl";
    # Consider sanitizing the environment even more.
    exec $named, '-f', '-c',  't/named.conf'
                or die "can't exec myprog: $!";
}


unlink("t/named.conf");
unlink("t/named-pid");
unlink("t/example.com");
unlink("t/example.com.jnl");
