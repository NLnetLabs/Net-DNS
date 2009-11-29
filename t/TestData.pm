# t::Testdata
# Stores some information for t/05-rr.t which is useful for reuse in other test modules that are not distributed.
# $Id$



require Exporter;
@ISA     = qw(Exporter );
use vars qw(  @rrs   @EXPORT  );
@EXPORT= qw (   @rrs  );


@rrs = (
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
		cname        => 'cname-cname.example.com.',
	}, 
	{   #[4]
		type         => 'DNAME',
		dname        => 'dname.example.com.',
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
		madname      => 'mb-madname.example.com.',
	}, 
	{	#[8]
		type         => 'MG',
		mgmname      => 'mg-mgmname.example.com.',
	}, 
	{	#[9]
		type         => 'MINFO',
		rmailbx      => 'minfo-rmailbx.example.com.',
		emailbx      => 'minfo-emailbx.example.com.',
	}, 
	{	#[10]
		type         => 'MR',
		newname      => 'mr-newname.example.com.',
	}, 
	{	#[11]
		type         => 'MX',
		preference   => 10,
		exchange     => 'mx-exchange.example.com.',
	},
	{	#[12]
		type         => 'NAPTR',
		order        => 100,
		preference   => 10,
		flags        => 'naptr-flags',
		service      => 'naptr-service',
		regexp       => 'naptr-regexp',
		replacement  => 'naptr-rEplacement.example.com.',
	},
	{	#[13]
		type         => 'NS',
		nsdname      => 'ns-nsdname.example.com.',
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
		ptrdname     => 'ptr-ptrdname.example.com.',
	},
	{	#[16] 
		type         => 'PX',
		preference   => 10,
		map822       => 'px-map822.example.com.',
		mapx400      => 'px-mapx400.example.com.',
	},
	{	#[17]
		type         => 'RP',
		mbox		 => 'rp-mbox.example.com.',
		txtdname     => 'rp-txtdname.example.com.',
	},
	{	#[18]
		type         => 'RT',
		preference   => 10,
		intermediate => 'rt-intermediate.example.com.',
	},
	{	#[19]
		type         => 'SOA',
		mname        => 'soa-mname.example.com.',
		rname        => 'soa-rname.example.com.',
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
		target       => 'srv-target.example.com.',
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

	{	#[25]
		type         => 'SPF',
		txtdata      => 'txt-txtdata',
	},
	
#   38.2.0.192.in-addr.arpa. 7200 IN     IPSECKEY ( 10 1 2
#                    192.0.2.38
#                    AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ== )

	{	#[26]
	        type           => 'IPSECKEY',
		precedence     => 10,
		algorithm      => 2,
		gatetype       => 1,
		gateway        => '192.0.2.38',
		pubkey         => "AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
	},



	{	#[27]
	        type           => 'IPSECKEY',
		precedence     => 10,
		algorithm      => 2,
		gatetype       => 0,
		gateway        => '.',
		pubkey         => "AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
	},


	{	#[28]
	        type           => 'IPSECKEY',
		precedence     => 10,
		algorithm      => 1,
		gatetype       => 2,
		gateway        => '2001:db8:0:8002:0:2000:1:0',
		pubkey         => "AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
	},



	{	#[28]
	        type           => 'IPSECKEY',
		precedence     => 10,
		algorithm      => 2,
		gatetype       => 3,
		gateway        => 'gateway.example.com.',
		pubkey         => "AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
	},
        {
	    type => 'HIP',
	    pkalgorithm => 2,
	    hit   => "200100107b1a74df365639cc39f1d578",
	    pubkey => "AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D",
	    rendezvousservers => [ qw|example.net example.com| ],
        },
    

);

1;
