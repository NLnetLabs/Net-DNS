# $Id$   -*-perl-*-

use Test::More;
use strict;

use vars qw( $HAS_DNSSEC );

my $keypathrsa="Kexample.com.+001+11567.private";
my $rsakeyrr;

BEGIN {
    if(
	eval {require Net::DNS::SEC;}
	){
	$HAS_DNSSEC=1;
	plan tests => 245;

    }else{
	$HAS_DNSSEC=0;
	plan tests => 219;
    }
};




if ($HAS_DNSSEC){  # Create key material    
    diag "The suite will run additonal DNSSEC tests";
    my $privrsakey= << 'ENDRSA' ;
Private-key-format: v1.2
Algorithm: 1 (RSA)
Modulus: 6ASwF3rSBFnBBQ7PmdWJnNkT2XkbZP5Be28SyTohsnuT1Rw7OlbNVNiT+4S04JUS0itVbvgtYmDZGMU3nfZP+er20uJRo/mu6hSkJW3MX5ES8o/GnOST1zSCH1+aA1Y6AlhfLebC+ysVKftLYnEco6oHNioYOmYHozYr5d0tL/s=
PublicExponent: Aw==
PrivateExponent: mq3KulHhWDvWA181ETkGaJC35lC87f7WUkoMhibBIae342gnfDneOJBip63N6w4MjBzjn1AeQZXmEIN6aU7f+q0Fwsyl4FzrSa8ehjfTS4u4YZE/Zk9rv0VIZuYwyccgLEBLYNBYRLbkbuSqDspw+Th8dCGy7XZ06eRkGZSNMjs=
Prime1: 9Fssra0OAl4kNX105Xdrnb7kS+/6QgWeJeBJCuajjWQ0uRiEClDzjVVVr6BW2DixP+6RCbSDioSIqsNc546UtQ==
Prime2: 8xMCAavFa+/XWHjnNJgCob976feJK2yaJrU7+2oxHiWLPtWYo+2gi2kt9Kv1aTp8lV327ddSqdO7tNJilsrP7w==
Exponent1: oudzHnNerD7CzlOjQ6TyaSnth/VRgVkUGUAwse8Xs5gjJhBYBuCiXjjjymrkkCXLf/RgsSMCXFhbHII977RjIw==
Exponent2: ogysAR0uR/U6OvtEzbqsa9T9RqUGHPMRbyN9UkbLaW5c1I5lwp5rB5tz+HKjm3xTDj6kno+McTfSeIxBudyKnw==
Coefficient: Cxwv14w+KY7rmiO4U0giXqOij9gON7TiByj5dQjHGUQdaQEJ0zK2SlxouEfgi3hcxTGI753pFmW0cF/MDjFURw==
ENDRSA


open (RSA,">$keypathrsa") or die "Could not open $keypathrsa";
    print RSA $privrsakey;
    close(RSA);
        
 $rsakeyrr=new Net::DNS::RR ("example.com. IN KEY 256 3 1 AQPoBLAXetIEWcEFDs+Z1Ymc2RPZeRtk/kF7bxLJOiGye5PVHDs6Vs1U 2JP7hLTglRLSK1Vu+C1iYNkYxTed9k/56vbS4lGj+a7qFKQlbcxfkRLy j8ac5JPXNIIfX5oDVjoCWF8t5sL7KxUp+0ticRyjqgc2Khg6ZgejNivl 3S0v+w==
");
    
    
    

    ok( $rsakeyrr, 'RSA public key created');     # test 5
    
    
}





BEGIN { use_ok('Net::DNS'); }

#------------------------------------------------------------------------------
# Canned data.
#------------------------------------------------------------------------------

my $name			= "foo.example.com";
my $class			= "IN";
my $ttl				= 43200;

my @rrs = (
	{  	#[0]
		type        => 'A',
	 	address     => '10.0.0.1',  
	}, 
	{	#[1]
		type        => 'AAAA',
		address     => '102:304:506:708:90a:b0c:d0e:ff10',
	}, 
	{	#[2]
		type         => 'AFSDB',
		subtype      => 1,
		hostname     => 'afsdb-hostname.example.com',
	}, 
	{	#[3]
		type         => 'CNAME',
		cname        => 'cname-cname.example.com',
	}, 
	{   #[4]
		type         => 'DNAME',
		dname        => 'dname.example.com',
	},
	{	#[5]
		type         => 'HINFO',
		cpu          => 'test-cpu',
		os           => 'test-os',
	}, 
	{	#[6]
		type         => 'ISDN',
		address      => '987654321',
		sa           => '001',
	}, 
	{	#[7]
		type         => 'MB',
		madname      => 'mb-madname.example.com',
	}, 
	{	#[8]
		type         => 'MG',
		mgmname      => 'mg-mgmname.example.com',
	}, 
	{	#[9]
		type         => 'MINFO',
		rmailbx      => 'minfo-rmailbx.example.com',
		emailbx      => 'minfo-emailbx.example.com',
	}, 
	{	#[10]
		type         => 'MR',
		newname      => 'mr-newname.example.com',
	}, 
	{	#[11]
		type         => 'MX',
		preference   => 10,
		exchange     => 'mx-exchange.example.com',
	},
	{	#[12]
		type         => 'NAPTR',
		order        => 100,
		preference   => 10,
		flags        => 'naptr-flags',
		service      => 'naptr-service',
		regexp       => 'naptr-regexp',
		replacement  => 'naptr-replacement.example.com',
	},
	{	#[13]
		type         => 'NS',
		nsdname      => 'ns-nsdname.example.com',
	},
	{	#[14]
		type         => 'NSAP',
		afi          => '47',
		idi          => '0005',
		dfi          => '80',
		aa           => '005a00',
		rd           => '1000',
		area         => '0020',
		id           => '00800a123456',
		sel          => '00',
	},
	{	#[15]
		type         => 'PTR',
		ptrdname     => 'ptr-ptrdname.example.com',
	},
	{	#[16] 
		type         => 'PX',
		preference   => 10,
		map822       => 'px-map822.example.com',
		mapx400      => 'px-mapx400.example.com',
	},
	{	#[17]
		type         => 'RP',
		mbox		 => 'rp-mbox.example.com',
		txtdname     => 'rp-txtdname.example.com',
	},
	{	#[18]
		type         => 'RT',
		preference   => 10,
		intermediate => 'rt-intermediate.example.com',
	},
	{	#[19]
		type         => 'SOA',
		mname        => 'soa-mname.example.com',
		rname        => 'soa-rname.example.com',
		serial       => 12345,
		refresh      => 7200,
		retry        => 3600,
		expire       => 2592000,
		minimum      => 86400,
	},
	{	#[20]
		type         => 'SRV',
		priority     => 1,
		weight       => 2,
		port         => 3,
		target       => 'srv-target.example.com',
	},
	{	#[21]
		type         => 'TXT',
		txtdata      => 'txt-txtdata',
	},
	{	#[22]
		type         => 'X25',
		psdn         => 123456789,
	},
	{	#[23]
		type         => 'LOC',
		version      => 0,
		size         => 3000,
		horiz_pre    => 500000,
		vert_pre     => 500,
		latitude     => 2001683648,
		longitude    => 1856783648,
		altitude     => 9997600,
	}, 	#[24]
	{
		type         => 'CERT',
		'format'     => 3,
		tag			 => 1,
		algorithm    => 1,
		certificate  => '123456789abcdefghijklmnopqrstuvwxyz',
	},
	
);





#------------------------------------------------------------------------------
# Create the packet and signatures (if DNSSEC is available.)
#------------------------------------------------------------------------------

my @rrsigs;
my $packet = Net::DNS::Packet->new($name);
ok($packet,         'Packet created');

foreach my $data (@rrs) {
    my $RR=Net::DNS::RR->new(
	   name => $name,
	   ttl  => $ttl,
	   %{$data});
       
       if ($HAS_DNSSEC){
	   my $sigrr= create Net::DNS::RR::RRSIG( [ $RR ],
						  $keypathrsa,
						  (
						   ttl => 360, 
						   sigval => 100,
						  ));
	   $sigrr->print;
	   push  @rrsigs, $sigrr;
       }
       

       $packet->push('answer', $RR );
}


#------------------------------------------------------------------------------
# Re-create the packet from data.
#------------------------------------------------------------------------------

my $data = $packet->data;
ok($data,            'Packet has data after pushes');

undef $packet;
$packet = Net::DNS::Packet->new(\$data);

ok($packet,          'Packet reconstructed from data');

my @answer = $packet->answer;

ok(@answer && @answer == @rrs, 'Packet returned correct answer section');





while (@answer and @rrs) {
	my $data = shift @rrs;
	my $rr   = shift @answer;
	my $type = $data->{'type'};
	
	ok($rr,                         "$type - RR defined");    
	is($rr->name,    $name,       	"$type - name() correct");         
	is($rr->class,   $class,      	"$type - class() correct");  
	is($rr->ttl,     $ttl,        	"$type - ttl() correct");                
	
	foreach my $meth (keys %{$data}) {
		
		is($rr->$meth(), $data->{$meth}, "$type - $meth() correct");
	}
	
	my $rr2 = Net::DNS::RR->new($rr->string);
	is($rr2->string, $rr->string,   "$type - Parsing from string works");
	if ($HAS_DNSSEC){
	    my $rrsig=shift @rrsigs;
	    ok($rrsig->verify([ $rr ], $rsakeyrr), "RR of type ".$type." signature creation/validation cycle");
	}
	
}






unlink($keypathrsa);
