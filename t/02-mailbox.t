# $Id$	-*-perl-*-

use strict;
use diagnostics;
use Test::More tests => 35;


BEGIN {
	use_ok('Net::DNS::Mailbox');
}


{
	my %testcase = (
		'.'				    => '<>',
		'a'				    => 'a',
		'a.b'				    => 'a@b',
		'a.b.c'				    => 'a@b.c',
		'a.b.c.d'			    => 'a@b.c.d',
		'a@b'				    => 'a@b',
		'a@b.c'				    => 'a@b.c',
		'a@b.c.d'			    => 'a@b.c.d',
		'a\.b.c.d'			    => 'a.b@c.d',
		'a\.b@c.d'			    => 'a.b@c.d',
		'a\@b.c.d'			    => 'a\@b@c.d',
		'a\@b@c.d'			    => 'a\@b@c.d',
		'empty <>'			    => '<>',
		'fore <a.b@c.d> aft'		    => 'a.b@c.d',
		'nested <<address>>'		    => 'address',
		'obscure <<left><<<deep>>><right>>' => 'right',
		);

	foreach my $test ( sort keys %testcase ) {
		my $expect  = $testcase{$test};
		my $mailbox = new Net::DNS::Mailbox($test);
		my $data    = $mailbox->encode;
		my $decoded = decode Net::DNS::Mailbox( \$data );
		is( $decoded->address, $expect, "encode/decode mailbox	$test" );
	}
}


{
	my $domain    = new Net::DNS::Mailbox( uc 'MBOX.EXAMPLE.COM' );
	my $hash      = {};
	my $data      = $domain->encode( 1, $hash );
	my $compress  = $domain->encode( length $data, $hash );
	my $canonical = $domain->encode( length $data );
	my $decoded   = decode Net::DNS::Mailbox( \$data );
	my $downcased = new Net::DNS::Mailbox( lc $domain->name )->encode( 0, {} );
	isa_ok( $domain,  'Net::DNS::Mailbox', 'object returned by new() constructor' );
	isa_ok( $decoded, 'Net::DNS::Mailbox', 'object returned by decode() constructor' );
	is( length $compress, length $data, 'Net::DNS::Mailbox encoding is uncompressed' );
	isnt( $data, $downcased, 'Net::DNS::Mailbox encoding preserves case' );
	is( length $canonical, length $data, 'Net::DNS::Mailbox canonical form is uncompressed' );
	isnt( $canonical, $downcased, 'Net::DNS::Mailbox canonical form preserves case' );
}


{
	my $domain    = new Net::DNS::Mailbox1035( uc 'MBOX.EXAMPLE.COM' );
	my $hash      = {};
	my $data      = $domain->encode( 1, $hash );
	my $compress  = $domain->encode( length $data, $hash );
	my $canonical = $domain->encode( length $data );
	my $decoded   = decode Net::DNS::Mailbox1035( \$data );
	my $downcased = new Net::DNS::Mailbox1035( lc $domain->name )->encode( 0, {} );
	isa_ok( $domain,  'Net::DNS::Mailbox1035', 'object returned by new() constructor' );
	isa_ok( $decoded, 'Net::DNS::Mailbox1035', 'object returned by decode() constructor' );
	isnt( length $compress, length $data, 'Net::DNS::Mailbox1035 encoding is compressible' );
	isnt( $data, $downcased, 'Net::DNS::Mailbox1035 encoding preserves case' );
	is( length $canonical, length $data, 'Net::DNS::Mailbox1035 canonical form is uncompressed' );
	is( $canonical, $downcased, 'Net::DNS::Mailbox1035 canonical form is lower case' );
}


{
	my $domain    = new Net::DNS::Mailbox2535( uc 'MBOX.EXAMPLE.COM' );
	my $hash      = {};
	my $data      = $domain->encode( 1, $hash );
	my $compress  = $domain->encode( length $data, $hash );
	my $canonical = $domain->encode( length $data );
	my $decoded   = decode Net::DNS::Mailbox2535( \$data );
	my $downcased = new Net::DNS::Mailbox2535( lc $domain->name )->encode( 0, {} );
	isa_ok( $domain,  'Net::DNS::Mailbox2535', 'object returned by new() constructor' );
	isa_ok( $decoded, 'Net::DNS::Mailbox2535', 'object returned by decode() constructor' );
	is( length $compress, length $data, 'Net::DNS::Mailbox2535 encoding is uncompressed' );
	isnt( $data, $downcased, 'Net::DNS::Mailbox2535 encoding preserves case' );
	is( length $canonical, length $data, 'Net::DNS::Mailbox2535 canonical form is uncompressed' );
	is( $canonical, $downcased, 'Net::DNS::Mailbox2535 canonical form is lower case' );
}


exit;

