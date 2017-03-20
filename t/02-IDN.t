# $Id$	-*-perl-*-

use strict;
use Test::More;


use constant UTF8 => scalar eval {	## not UTF-EBCDIC  [see UTR#16 3.6]
	require Encode;
	Encode::encode_utf8( chr(160) ) eq pack( 'H*', 'C2A0' );
};

use constant LIBIDN => defined eval { require Net::LibIDN; };

use constant LIBIDNOK => LIBIDN && scalar eval {
	my $cn = pack( 'U*', 20013, 22269 );
	Net::LibIDN::idn_to_ascii( $cn, 'utf-8' ) eq 'xn--fiqs8s';
};


plan skip_all => 'Unicode/UTF-8 not supported' unless UTF8;

plan skip_all => 'Net::LibIDN not installed' unless LIBIDN;

plan skip_all => 'Net::LibIDN not working' unless LIBIDNOK;

plan tests => 10;


use_ok('Net::DNS::Domain');


my $a_label = 'xn--fiqs8s';
my $u_label = eval { pack( 'U*', 20013, 22269 ); };
is( new Net::DNS::Domain($a_label)->name,   $a_label,	 'IDN A-label domain->name' );
is( new Net::DNS::Domain($a_label)->fqdn,   "$a_label.", 'IDN A-label domain->fqdn' );
is( new Net::DNS::Domain($a_label)->xname,  $u_label,	 'IDN A-label domain->xname' );
is( new Net::DNS::Domain($a_label)->string, "$a_label.", 'IDN A-label domain->string' );


is( new Net::DNS::Domain($u_label)->name,  $a_label,	'IDN U-label domain->name' );
is( new Net::DNS::Domain($u_label)->fqdn,  "$a_label.", 'IDN U-label domain->fqdn' );
is( new Net::DNS::Domain($u_label)->xname, $u_label,	'IDN U-label domain->xname' );
new Net::DNS::Domain($u_label)->xname;				# exercise cache path
is( new Net::DNS::Domain($u_label)->string, "$a_label.", 'IDN U-label domain->string' );


eval { new Net::DNS::Domain( pack 'H*', 'C200' ); };
my $exception = $1 if $@ =~ /^(.+)\n/;
ok( $exception ||= '', "invalid name\t[$exception]" );


exit;

