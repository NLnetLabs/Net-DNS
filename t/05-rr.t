# $Id: 05-rr.t,v 1.5 2002/03/26 22:48:55 ctriv Exp $

use Test::More tests => 202;
use strict;


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
	{	#[4]
		type         => 'HINFO',
		cpu          => 'test-cpu',
		os           => 'test-os',
	}, 
	{	#[5]
		type         => 'ISDN',
		address      => '987654321',
		sa           => '001',
	}, 
	{	#[6]
		type         => 'MB',
		madname      => 'mb-madname.example.com',
	}, 
	{	#[7]
		type         => 'MG',
		mgmname      => 'mg-mgmname.example.com',
	}, 
	{	#[8]
		type         => 'MINFO',
		rmailbx      => 'minfo-rmailbx.example.com',
		emailbx      => 'minfo-emailbx.example.com',
	}, 
	{	#[9]
		type         => 'MR',
		newname      => 'mr-newname.example.com',
	}, 
	{	#[10]
		type         => 'MX',
		preference   => 10,
		exchange     => 'mx-exchange.example.com',
	},
	{	#[11]
		type         => 'NAPTR',
		order        => 100,
		preference   => 10,
		flags        => 'naptr-flags',
		service      => 'naptr-service',
		regexp       => 'naptr-regexp',
		replacement  => 'naptr-replacement.example.com',
	},
	{	#[12]
		type         => 'NS',
		nsdname      => 'ns-nsdname.example.com',
	},
	{	#[13]
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
	{	#[14]
		type         => 'PTR',
		ptrdname     => 'ptr-ptrdname.example.com',
	},
	{	#[15] 
		type         => 'PX',
		preference   => 10,
		map822       => 'px-map822.example.com',
		mapx400      => 'px-mapx400.example.com',
	},
	{	#[16]
		type         => 'RP',
		mbox		 => 'rp-mbox.example.com',
		txtdname     => 'rp-txtdname.example.com',
	},
	{	#[17]
		type         => 'RT',
		preference   => 10,
		intermediate => 'rt-intermediate.example.com',
	},
	{	#[18]
		type         => 'SOA',
		mname        => 'soa-mname.example.com',
		rname        => 'soa-rname.example.com',
		serial       => 12345,
		refresh      => 7200,
		retry        => 3600,
		expire       => 2592000,
		minimum      => 86400,
	},
	{	#[19]
		type         => 'SRV',
		priority     => 1,
		weight       => 2,
		port         => 3,
		target       => 'srv-target.example.com',
	},
	{	#[20]
		type         => 'TXT',
		txtdata      => 'txt-txtdata',
	},
	{	#[21]
		type         => 'X25',
		psdn         => 123456789,
	},
	{	#[22]
		type         => 'LOC',
		version      => 0,
		size         => 3000,
		horiz_pre    => 500000,
		vert_pre     => 500,
		latitude     => 2001683648,
		longitude    => 1856783648,
		altitude     => 9997600,
	},
);

#------------------------------------------------------------------------------
# Create the packet.
#------------------------------------------------------------------------------

my $packet = Net::DNS::Packet->new($name);
ok($packet,         'Packet created');

foreach my $data (@rrs) {
	$packet->push('answer', 
		Net::DNS::RR->new(
			name => $name,
			ttl  => $ttl,
			%{$data},
		)
	);
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
		
		is($rr->$meth, $data->{$meth}, "$type - $meth() correct");
	}
	
	SKIP: {
		skip "Net::DNS::RR::${type}::new_from_string is not implemented", 1
			if $type eq 'NSAP';
		
		my $rr2 = Net::DNS::RR->new($rr->string);
		is($rr2->string, $rr->string,   "$type - Parsing from string works");
	}
}


