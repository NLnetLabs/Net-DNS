# $Id$	-*-perl-*-

use strict;
use Test::More;
use Net::DNS;

my %prerequisite = (
	'Digest::HMAC' => 1.03,
	'Digest::MD5'  => 2.13,
	'Digest::SHA'  => 5.23,
	'MIME::Base64' => 2.13,
	);

foreach my $package ( sort keys %prerequisite ) {
	my @revision = grep $_, $prerequisite{$package};
	next if eval "use $package @revision; 1;";
	plan skip_all => "missing prerequisite $package @revision";
	exit;
}

plan tests => 12;


my $tsig = new Net::DNS::RR( type => 'TSIG' );
my $class = ref($tsig);


my $keyrr = new Net::DNS::RR <<'END';
hmac-md5.example. IN KEY 512 3 157 ARDJZgtuTDzAWeSGYPAu9uJUkX0=
END

my $privatekey = $keyrr->privatekeyname;
END { unlink($privatekey) if defined $privatekey; }

open( KEY, ">$privatekey" ) or die "$privatekey $!";
print KEY <<'END';
Private-key-format: v1.2
Algorithm: 157 (HMAC_MD5)
Key: ARDJZgtuTDzAWeSGYPAu9uJUkX0=
END
close KEY;

{
	my $tsig = create $class($privatekey);
	is( ref($tsig), $class, 'create TSIG from private key' );
}


{
	my $tsig = create $class($keyrr);
	is( ref($tsig), $class, 'create TSIG from KEY RR' );
}


my $publickey = 'Khmac-sha1.example.+161+39562.key';
END { unlink($publickey) if defined $publickey; }

open( KEY, ">$publickey" ) or die "$publickey $!";
print KEY <<'END';
HMAC-SHA1.example. IN KEY 512 3 161 xdX9m8UtQNbJUzUgQ4xDtUNZAmU=
END
close KEY;

{
	my $tsig = create $class($publickey);
	is( ref($tsig), $class, 'create TSIG from public key' );
}


{
	my $packet = new Net::DNS::Packet('query.example');
	$packet->sign_tsig($privatekey);
	my $tsig = create $class($packet);
	is( ref($tsig), $class, 'create TSIG from signed packet' );
}


{
	my $chain = eval { create $class($tsig); };
	is( ref($chain), $class, 'create successor to existing TSIG' );
}


{
	eval { create $class(); };
	my ($exception) = split /\n/, "$@\n";
	ok( $exception, "empty argument list\t[$exception]" );
}


{
	eval { create $class(undef); };
	my ($exception) = split /\n/, "$@\n";
	ok( $exception, "argument undefined\t[$exception]" );
}


{
	my $null = new Net::DNS::RR( type => 'NULL' );
	eval { create $class($null); };
	my ($exception) = split /\n/, "$@\n";
	ok( $exception, "unexpected argument\t[$exception]" );
}


{
	my $packet = new Net::DNS::Packet('query.example');
	eval { create $class($packet); };
	my ($exception) = split /\n/, "$@\n";
	ok( $exception, "no TSIG in packet\t[$exception]" );
}


my $badprivatekey = 'K+161+39562.private';
END { unlink($badprivatekey) if defined $badprivatekey; }

open( KEY, ">$badprivatekey" ) or die "$badprivatekey $!";
print KEY <<'END';
Private-key-format: v1.2
Algorithm: 161 (HMAC_SHA1)
Key: xdX9m8UtQNbJUzUgQ4xDtUNZAmU=
END
close KEY;

{
	eval { create $class($badprivatekey); };
	my ($exception) = split /\n/, "$@\n";
	ok( $exception, "misnamed private key\t[$exception]" );
}


my $dnskey = 'Kbad.example.+161+39562.key';
END { unlink($dnskey) if defined $dnskey; }

open( KEY, ">$dnskey" ) or die "$dnskey $!";
print KEY <<'END';
HMAC-SHA1.example. IN DNSKEY 512 3 161 xdX9m8UtQNbJUzUgQ4xDtUNZAmU=
END
close KEY;

{
	eval { create $class($dnskey); };
	my ($exception) = split /\n/, "$@\n";
	ok( $exception, "unrecognised public key\t[$exception]" );
}


{
	my @warning;
	local $SIG{__WARN__} = sub { @warning = @_ };
	create $class( $keyrr->owner, $keyrr->key );
	my ($warning) = split /\n/, "@warning\n";
	ok( $warning, "2-argument create:\t[$warning]" );
}


__END__

