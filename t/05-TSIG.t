# $Id$	-*-perl-*-

use strict;

BEGIN {
	use Test::More;
	use Net::DNS;

	my @prerequisite = qw(
		Digest::HMAC
		Digest::MD5
		Digest::SHA
		MIME::Base64
		);

	foreach my $package (@prerequisite) {
		plan skip_all => "$package not installed"
			unless eval "require $package";
	}

	plan tests => 53;
}


sub mysign {
	my ( $key, $data ) = @_;
	my $hmac = new Digest::HMAC( $key, 'Digest::MD5' );
	$hmac->add($data);
	return $hmac->digest;
}


my $name = '123456789-test';
my $type = 'TSIG';
my $code = 250;
my @attr = qw(	algorithm	time_signed	fudge	sig_function );
my @data = ( qw( fake.alg	100001		600 ), \&mysign );
my @also = qw( mac macbin error other );

my $wire = '0466616b6503616c67000000000186a102580010a5d31d3ce3b7122b4a598c225d9c3f2a04d200000000';


my $hash = {};
@{$hash}{@attr} = @data;


{
	my $typecode = unpack 'xn', new Net::DNS::RR(". $type")->encode;
	is( $typecode, $code, "$type RR type code = $code" );

	my $rr = new Net::DNS::RR(
		name => $name,
		type => $type,
		%$hash,
		keybin => 'fake key',
		);

	my $string = $rr->string;
	like( $rr->string, "/$$hash{algorithm}/", 'got expected rr->string' );

	foreach (@attr) {
		is( $rr->$_, $hash->{$_}, "expected result from rr->$_()" );
	}

	foreach (@also) {
		ok( defined $rr->$_, "additional attribute rr->$_()" );
	}


	my $null   = new Net::DNS::RR("$name NULL")->encode;
	my $empty  = new Net::DNS::RR("$name $type")->encode;
	my $buffer = $empty;		## Note: TSIG RR gets destroyed by decoder
	my $rxbin  = decode Net::DNS::RR( \$buffer )->encode;
	my $packet = Net::DNS::Packet->new( $name, 'TKEY', 'IN' );
	$packet->header->id(1234);				# fix packet id
	my $encoded = $buffer = $rr->encode( 0, {}, $packet );
	my $decoded = decode Net::DNS::RR( \$buffer );
	my $hex1    = unpack 'H*', $encoded;
	my $hex2    = unpack 'H*', $decoded->encode;
	my $hex3    = unpack 'H*', substr( $encoded, length $null );
	is( $hex2,	    $hex1,	   'encode/decode transparent' );
	is( $hex3,	    $wire,	   'encoded RDATA matches example' );
	is( length($empty), length($null), 'encoded RDATA can be empty' );
	is( length($rxbin), length($null), 'decoded RDATA can be empty' );
}


{
	# Check default signing function using test cases from RFC2202, section 2.

	my $tsig = new Net::DNS::RR( type => 'TSIG', fudge => 300 );
	my $function  = $tsig->sig_function;			# default signing function
	my $algorithm = $tsig->algorithm;			# default algorithm

	is( $algorithm, 'HMAC-MD5.SIG-ALG.REG.INT', 'Check algorithm correctly identified' );
	{
		my $key    = "\x0b" x 16;
		my $data   = "Hi There";
		my $result = lc unpack( 'H*', &$function( $key, $data ) );
		my $expect = '9294727a3638bb1c13f48ef8158bfc9d';
		is( $result, $expect, "Check signing function for $algorithm" );
	}

	{
		my $key    = "Jefe";
		my $data   = "what do ya want for nothing?";
		my $result = lc unpack( 'H*', &$function( $key, $data ) );
		my $expect = '750c783e6ab0b503eaa86e310a5db738';
		is( $result, $expect, "Check $algorithm with key shorter than hash size" );
	}

	{
		my $key    = "\xaa" x 16;
		my $data   = "\xdd" x 50;
		my $result = lc unpack( 'H*', &$function( $key, $data ) );
		my $expect = '56be34521d144c88dbb8c733f0e8b3f6';
		is( $result, $expect, "Check $algorithm with data longer than hash size" );
	}

	{
		my $key    = pack 'H*', '0102030405060708090a0b0c0d0e0f10111213141516171819';
		my $data   = "\xcd" x 50;
		my $result = lc unpack( 'H*', &$function( $key, $data ) );
		my $expect = '697eaf0aca3a3aea3a75164746ffaa79';
		is( $result, $expect, "Check $algorithm with key and data longer than hash" );
	}

	{
		my $key    = "\xaa" x 80;
		my $data   = "Test Using Larger Than Block-Size Key - Hash Key First";
		my $result = lc unpack( 'H*', &$function( $key, $data ) );
		my $expect = '6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd';
		is( $result, $expect, "Check $algorithm with key longer than block size" );
	}

	{
		my $key    = "\xaa" x 80;
		my $data   = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";
		my $result = lc unpack( 'H*', &$function( $key, $data ) );
		my $expect = '6f630fad67cda0ee1fb1f562db3aa53e';
		is( $result, $expect, "Check $algorithm with both long key and long data" );
	}
}


{
	# Check HMAC-SHA1 signing function using test cases from RFC2202, section 3.

	my $tsig = new Net::DNS::RR( type => 'TSIG', algorithm => 'HMAC-SHA' );	# alias HMAC-SHA1
	my $algorithm = $tsig->algorithm;
	my $function  = $tsig->sig_function;

	is( $algorithm, 'HMAC-SHA1', 'Check algorithm correctly identified' );
	{
		my $key    = "\x0b" x 20;
		my $data   = "Hi There";
		my $result = lc unpack( 'H*', &$function( $key, $data ) );
		my $expect = 'b617318655057264e28bc0b6fb378c8ef146be00';
		is( $result, $expect, "Check signing function for $algorithm" );
	}

	{
		my $key    = "Jefe";
		my $data   = "what do ya want for nothing?";
		my $result = lc unpack( 'H*', &$function( $key, $data ) );
		my $expect = 'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79';
		is( $result, $expect, "Check $algorithm with key shorter than hash size" );
	}

	{
		my $key    = "\xaa" x 20;
		my $data   = "\xdd" x 50;
		my $result = lc unpack( 'H*', &$function( $key, $data ) );
		my $expect = '125d7342b9ac11cd91a39af48aa17b4f63f175d3';
		is( $result, $expect, "Check $algorithm with data longer than hash size" );
	}

	{
		my $key    = pack 'H*', '0102030405060708090a0b0c0d0e0f10111213141516171819';
		my $data   = "\xcd" x 50;
		my $result = lc unpack( 'H*', &$function( $key, $data ) );
		my $expect = '4c9007f4026250c6bc8414f9bf50c86c2d7235da';
		is( $result, $expect, "Check $algorithm with key and data longer than hash" );
	}

	{
		my $key    = "\xaa" x 80;
		my $data   = "Test Using Larger Than Block-Size Key - Hash Key First";
		my $result = lc unpack( 'H*', &$function( $key, $data ) );
		my $expect = 'aa4ae5e15272d00e95705637ce8a3b55ed402112';
		is( $result, $expect, "Check $algorithm with key longer than block size" );
	}

	{
		my $key    = "\xaa" x 80;
		my $data   = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";
		my $result = lc unpack( 'H*', &$function( $key, $data ) );
		my $expect = 'e8e99d0f45237d786d6bbaa7965c7808bbff1a91';
		is( $result, $expect, "Check $algorithm with both long key and long data" );
	}
}


{
	# Check HMAC-SHA224 signing function using test cases from RFC4634, section 8.4.

	my $tsig = new Net::DNS::RR( type => 'TSIG', algorithm => 162 );	# alias HMAC-SHA224
	my $algorithm = $tsig->algorithm;
	my $function  = $tsig->sig_function;

	is( $algorithm, 'HMAC-SHA224', 'Check algorithm correctly identified' );
	{
		my $key    = "\x0b" x 20;
		my $data   = "Hi There";
		my $result = uc unpack( 'H*', &$function( $key, $data ) );
		my $expect = '896FB1128ABBDF196832107CD49DF33F47B4B1169912BA4F53684B22';
		is( $result, $expect, "Check signing function for $algorithm" );
	}

	{
		my $key    = "Jefe";
		my $data   = "what do ya want for nothing?";
		my $result = uc unpack( 'H*', &$function( $key, $data ) );
		my $expect = 'A30E01098BC6DBBF45690F3A7E9E6D0F8BBEA2A39E6148008FD05E44';
		is( $result, $expect, "Check $algorithm with key shorter than hash size" );
	}

	{
		my $key    = "\xaa" x 20;
		my $data   = "\xdd" x 50;
		my $result = uc unpack( 'H*', &$function( $key, $data ) );
		my $expect = '7FB3CB3588C6C1F6FFA9694D7D6AD2649365B0C1F65D69D1EC8333EA';
		is( $result, $expect, "Check $algorithm with data longer than hash size" );
	}

	{
		my $key    = pack 'H*', '0102030405060708090a0b0c0d0e0f10111213141516171819';
		my $data   = "\xcd" x 50;
		my $result = uc unpack( 'H*', &$function( $key, $data ) );
		my $expect = '6C11506874013CAC6A2ABC1BB382627CEC6A90D86EFC012DE7AFEC5A';
		is( $result, $expect, "Check $algorithm with key and data longer than hash" );
	}

	{
		my $key    = "\xaa" x 131;
		my $data   = "Test Using Larger Than Block-Size Key - Hash Key First";
		my $result = uc unpack( 'H*', &$function( $key, $data ) );
		my $expect = '95E9A0DB962095ADAEBE9B2D6F0DBCE2D499F112F2D2B7273FA6870E';
		is( $result, $expect, "Check $algorithm with key longer than block size" );
	}

	{
		my $key    = "\xaa" x 131;
		my $data   = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
		my $result = uc unpack( 'H*', &$function( $key, $data ) );
		my $expect = '3A854166AC5D9F023F54D517D0B39DBD946770DB9C2B95C9F6F565D1';
		is( $result, $expect, "Check $algorithm with both long key and long data" );
	}
}


{
	# Check HMAC-SHA256 signing function using test cases from RFC4634, section 8.4.

	my $tsig = new Net::DNS::RR( type => 'TSIG', algorithm => 'HMAC-SHA256' );
	my $algorithm = $tsig->algorithm;
	my $function  = $tsig->sig_function;

	{
		my $key    = "\x0b" x 20;
		my $data   = "Hi There";
		my $result = uc unpack( 'H*', &$function( $key, $data ) );
		my $expect = 'B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7';
		is( $result, $expect, "Check signing function for $algorithm" );
	}

	{
		my $key    = "Jefe";
		my $data   = "what do ya want for nothing?";
		my $result = uc unpack( 'H*', &$function( $key, $data ) );
		my $expect = '5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843';
		is( $result, $expect, "Check $algorithm with key shorter than hash size" );
	}

	{
		my $key    = "\xaa" x 20;
		my $data   = "\xdd" x 50;
		my $result = uc unpack( 'H*', &$function( $key, $data ) );
		my $expect = '773EA91E36800E46854DB8EBD09181A72959098B3EF8C122D9635514CED565FE';
		is( $result, $expect, "Check $algorithm with data longer than hash size" );
	}

	{
		my $key    = pack 'H*', '0102030405060708090a0b0c0d0e0f10111213141516171819';
		my $data   = "\xcd" x 50;
		my $result = uc unpack( 'H*', &$function( $key, $data ) );
		my $expect = '82558A389A443C0EA4CC819899F2083A85F0FAA3E578F8077A2E3FF46729665B';
		is( $result, $expect, "Check $algorithm with key and data longer than hash" );
	}

	{
		my $data   = "Test Using Larger Than Block-Size Key - Hash Key First";
		my $output = &$function( "\xaa" x 131, $data );
		my $result = uc unpack( 'H*', $output );
		my $expect = '60E431591EE0B67F0D8A26AACBF5B77F8E0BC6213728C5140546040F0EE37F54';
		is( $result, $expect, "Check $algorithm with key longer than block size" );
	}

	{
		my $data   = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
		my $output = &$function( "\xaa" x 131, $data );
		my $result = uc unpack( 'H*', $output );
		my $expect = '9B09FFA71B942FCB27635FBCD5B0E944BFDC63644F0713938A7F51535C3A35E2';
		is( $result, $expect, "Check $algorithm with both long key and long data" );
	}
}


{
	# Check HMAC-SHA384 signing function using test cases from RFC4634, section 8.4.

	my $tsig = new Net::DNS::RR( type => 'TSIG', algorithm => 'HMAC-SHA384' );
	my $algorithm = $tsig->algorithm;
	my $function  = $tsig->sig_function;

	{
		my $key    = "\x0b" x 20;
		my $data   = "Hi There";
		my $result = uc unpack( 'H*', &$function( $key, $data ) );
		my $expect = 'AFD03944D84895626B0825F4AB46907F15F9DADBE4101EC682AA034C7CEBC59CFAEA9EA9076EDE7F4AF152E8B2FA9CB6';
		is( $result, $expect, "Check signing function for $algorithm" );
	}

	{
		my $key    = "Jefe";
		my $data   = "what do ya want for nothing?";
		my $result = uc unpack( 'H*', &$function( $key, $data ) );
		my $expect = 'AF45D2E376484031617F78D2B58A6B1B9C7EF464F5A01B47E42EC3736322445E8E2240CA5E69E2C78B3239ECFAB21649';
		is( $result, $expect, "Check $algorithm with key shorter than hash size" );
	}

	{
		my $key    = "\xaa" x 20;
		my $data   = "\xdd" x 50;
		my $result = uc unpack( 'H*', &$function( $key, $data ) );
		my $expect = '88062608D3E6AD8A0AA2ACE014C8A86F0AA635D947AC9FEBE83EF4E55966144B2A5AB39DC13814B94E3AB6E101A34F27';
		is( $result, $expect, "Check $algorithm with data longer than hash size" );
	}

	{
		my $key    = pack 'H*', '0102030405060708090a0b0c0d0e0f10111213141516171819';
		my $data   = "\xcd" x 50;
		my $result = uc unpack( 'H*', &$function( $key, $data ) );
		my $expect = '3E8A69B7783C25851933AB6290AF6CA77A9981480850009CC5577C6E1F573B4E6801DD23C4A7D679CCF8A386C674CFFB';
		is( $result, $expect, "Check $algorithm with key and data longer than hash" );
	}

	{
		my $data   = "Test Using Larger Than Block-Size Key - Hash Key First";
		my $output = &$function( "\xaa" x 131, $data );
		my $result = uc unpack( 'H*', $output );
		my $expect = '4ECE084485813E9088D2C63A041BC5B44F9EF1012A2B588F3CD11F05033AC4C60C2EF6AB4030FE8296248DF163F44952';
		is( $result, $expect, "Check $algorithm with key longer than block size" );
	}

	{
		my $data   = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
		my $output = &$function( "\xaa" x 131, $data );
		my $result = uc unpack( 'H*', $output );
		my $expect = '6617178E941F020D351E2F254E8FD32C602420FEB0B8FB9ADCCEBB82461E99C5A678CC31E799176D3860E6110C46523E';
		is( $result, $expect, "Check $algorithm with both long key and long data" );
	}
}


{
	# Check HMAC-SHA512 signing function using test cases from RFC4634, section 8.4.

	my $tsig = new Net::DNS::RR( type => 'TSIG', algorithm => 'HMAC-SHA512' );
	my $algorithm = $tsig->algorithm;
	my $function  = $tsig->sig_function;

	{
		my $key    = "\x0b" x 20;
		my $data   = "Hi There";
		my $result = uc unpack( 'H*', &$function( $key, $data ) );
		my $expect = '87AA7CDEA5EF619D4FF0B4241A1D6CB02379F4E2CE4EC2787AD0B30545E17CDEDAA833B7D6B8A702038B274EAEA3F4E4BE9D914EEB61F1702E696C203A126854';
		is( $result, $expect, "Check signing function for $algorithm" );
	}

	{
		my $key    = "Jefe";
		my $data   = "what do ya want for nothing?";
		my $result = uc unpack( 'H*', &$function( $key, $data ) );
		my $expect = '164B7A7BFCF819E2E395FBE73B56E0A387BD64222E831FD610270CD7EA2505549758BF75C05A994A6D034F65F8F0E6FDCAEAB1A34D4A6B4B636E070A38BCE737';
		is( $result, $expect, "Check $algorithm with key shorter than hash size" );
	}

	{
		my $key    = "\xaa" x 20;
		my $data   = "\xdd" x 50;
		my $result = uc unpack( 'H*', &$function( $key, $data ) );
		my $expect = 'FA73B0089D56A284EFB0F0756C890BE9B1B5DBDD8EE81A3655F83E33B2279D39BF3E848279A722C806B485A47E67C807B946A337BEE8942674278859E13292FB';
		is( $result, $expect, "Check $algorithm with data longer than hash size" );
	}

	{
		my $key    = pack 'H*', '0102030405060708090a0b0c0d0e0f10111213141516171819';
		my $data   = "\xcd" x 50;
		my $result = uc unpack( 'H*', &$function( $key, $data ) );
		my $expect = 'B0BA465637458C6990E5A8C5F61D4AF7E576D97FF94B872DE76F8050361EE3DBA91CA5C11AA25EB4D679275CC5788063A5F19741120C4F2DE2ADEBEB10A298DD';
		is( $result, $expect, "Check $algorithm with key and data longer than hash" );
	}

	{
		my $data   = "Test Using Larger Than Block-Size Key - Hash Key First";
		my $output = &$function( "\xaa" x 131, $data );
		my $result = uc unpack( 'H*', $output );
		my $expect = '80B24263C7C1A3EBB71493C1DD7BE8B49B46D1F41B4AEEC1121B013783F8F3526B56D037E05F2598BD0FD2215D6A1E5295E64F73F63F0AEC8B915A985D786598';
		is( $result, $expect, "Check $algorithm with key longer than block size" );
	}

	{
		my $data   = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
		my $output = &$function( "\xaa" x 131, $data );
		my $result = uc unpack( 'H*', $output );
		my $expect = 'E37B6A775DC87DBAA4DFA9F96E5E3FFDDEBD71F8867289865DF5A32D20CDC944B6022CAC3C4982B10D5EEB55C3E4DE15134676FB6DE0446065C97440FA8C6A58';
		is( $result, $expect, "Check $algorithm with both long key and long data" );
	}
}


exit;

