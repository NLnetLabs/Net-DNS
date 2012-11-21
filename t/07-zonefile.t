# $Id$	-*-perl-*-

use strict;
use FileHandle;

use Test::More tests => 46;

use t::NonFatal;

use constant UTF8 => eval {
	require Encode;
	die if Encode::decode_utf8( chr(91) ) ne '[';		# not UTF-EBCDIC  [see UTR#16 3.6]
	Encode::find_encoding('UTF8');
} || 0;

use constant LIBIDN => eval {					# optional IDN support
	require Net::LibIDN;
	Net::LibIDN::idn_to_ascii( pack( 'U*', 20013, 22269 ), 'utf-8' ) eq 'xn--fiqs8s';
} || 0;


BEGIN {
	use_ok('Net::DNS::ZoneFile');
}


NonFatalBegin();


my $seq;

sub source {				## zone file builder
	my $text = shift;

	my $tag	 = ++$seq;
	my $file = "zone$tag.txt";

	my $handle = new FileHandle( $file, '>' ) unless UTF8;
	$handle = new FileHandle( $file, '>:encoding(UTF-8)' ) if UTF8;
	die "Failed to open $file" unless $handle;

	print $handle $text;
	close $handle;

	return new Net::DNS::ZoneFile($file);
}


{				## public methods
	my $zonefile = source('');
	isa_ok( $zonefile, 'Net::DNS::ZoneFile', 'new ZoneFile object' );

	ok( defined $zonefile->name,   'zonefile->name always defined' );
	ok( defined $zonefile->line,   'zonefile->line always defined' );
	ok( defined $zonefile->origin, 'zonefile->origin always defined' );
	ok( defined $zonefile->ttl,    'zonefile->ttl always defined' );
	my @rr = $zonefile->read;
	is( scalar @rr,	     0, 'zonefile->read to end of file' );
	is( $zonefile->line, 0, 'zonefile->line zero if file empty' );
}


{				## line numbering
	my $lines    = 10;
	my $zonefile = source( "\n" x $lines );
	is( $zonefile->line, 0, 'zonefile->line zero before calling read()' );
	my @rr = $zonefile->read;
	is( $zonefile->line, $lines, 'zonefile->line number incremented by read()' );
}


{				## CLASS coersion
	my $zonefile = source <<'EOF';
rr0	CH	NULL
rr1	CLASS1	NULL
rr2	CLASS2	NULL
rr3	CLASS3	NULL
EOF
	my $rr = $zonefile->read;
	foreach ( $zonefile->read ) {
		is( $_->class, $rr->class, 'rr->class matches initial record' );
	}
}


{				## $TTL directive
	my $zonefile = source <<'EOF';
rr0		SOA	mname rname 99 6h 1h 1w 12345
rr1		NULL
$TTL 54321
rr2		NULL
rr3	3h	NULL
EOF
	is( $zonefile->read->ttl, 12345, 'SOA TTL set from SOA minimum field' );
	is( $zonefile->read->ttl, 12345, 'implicit default from SOA record' );
	is( $zonefile->read->ttl, 54321, 'explicit default from $TTL directive' );
	is( $zonefile->read->ttl, 10800, 'explicit TTL value overrides default' );
}


{				## $INCLUDE directive
	my $include = source <<'EOF';
rr2	NULL
EOF

	my $directive = join ' ', '$INCLUDE', $include->name;
	my $misdirect = join ' ', '$INCLUDE zone0.txt	; presumed not to exist';
	my $zonefile  = source <<"EOF";
rr1	NULL
$directive 
rr3	NULL
$misdirect 
EOF

	my $fn1 = $zonefile->name;
	my $rr1 = $zonefile->read;
	is( $rr1->name,	     'rr1', 'zonefile->read expected record' );
	is( $zonefile->name, $fn1,  'zonefile->name identifies file' );
	is( $zonefile->line, 1,	    'zonefile->line identifies record' );

	my $fn2 = $include->name;
	my $rr2 = $zonefile->read;
	my $sfx = $zonefile->origin;
	is( $rr2->name,	     'rr2', 'zonefile->read expected record' );
	is( $zonefile->name, $fn2,  'zonefile->name identifies file' );
	is( $zonefile->line, 1,	    'zonefile->line identifies record' );

	my $rr3 = $zonefile->read;
	is( $rr3->name,	     'rr3', 'zonefile->read expected record' );
	is( $zonefile->name, $fn1,  'zonefile->name identifies file' );
	is( $zonefile->line, 3,	    'zonefile->line identifies record' );

	my @rr = eval { $zonefile->read };
	my $exception = $1 if $@ =~ /^(.+)\n/;
	ok( $exception ||= '', "try non-existent include file\t[$exception]" );
	is( $zonefile->name, $fn1, 'zonefile->name identifies file' );
	is( $zonefile->line, 4,	   'zonefile->line identifies directive' );
}


{				## $ORIGIN directive
	my $nested = source <<'EOF';
nested	NULL
EOF

	my $inner = join ' ', '$INCLUDE', $nested->name;
	my $include = source <<"EOF";
@	NS	host
$inner 
@	NULL
EOF

	my $outer = join ' ', '$INCLUDE', $include->name, 'example.com';
	my $zonefile = source <<"EOF";
$outer 
outer	NULL
EOF

	my $ns	   = $zonefile->read;
	my $origin = $zonefile->origin;
	is( $ns->name,	  $origin,	  '@	NS	has expected name' );
	is( $ns->nsdname, "host.$origin", '@	NS	has expected rdata' );

	my $rr = $zonefile->read;
	my $expect = join '.', 'nested', $origin;
	is( $rr->name, $expect, 'scope of $ORIGIN encompasses nested $INCLUDE' );

	is( $zonefile->read->name, $origin, 'scope of $ORIGIN continues after $INCLUDE' );

	is( $zonefile->read->name, 'outer', 'scope of $ORIGIN curtailed by end of file' );
}


{				## $GENERATE directive
	my $zonefile = source <<'EOF';
$GENERATE 10-30/10	@	MX	$ mail
$GENERATE 30-10/-10	@	MX	$ mail
EOF
	is( $zonefile->read->preference, 10, 'generate MX preference with step 10' );
	is( $zonefile->read->preference, 20, 'generate MX preference with step 10' );
	is( $zonefile->read->preference, 30, 'generate MX preference with step 10' );
	is( $zonefile->read->preference, 30, 'generate MX preference with step -10' );
	is( $zonefile->read->preference, 20, 'generate MX preference with step -10' );
	is( $zonefile->read->preference, 10, 'generate MX preference with step -10' );
}


SKIP: {				## Non-ASCII zone file content
	skip( 'Non-ASCII content - Unicode/UTF-8 not supported', 2 ) unless UTF8;

	my $zonefile = source <<'EOF';
jp	TXT	"古池や　蛙飛込む　水の音"		; Unicode string
日本	NULL						; Unicode domain name
EOF

	my $txt = $zonefile->read;
	my @txt = $txt->txtdata;
	is( length( $txt[0] ), 12, 'Non-ASCII TXT argument' );

	skip( 'Non-ASCII domain - Net::LibIDN not available', 1 ) unless LIBIDN;
	my $rr = $zonefile->read;
	is( $rr->name, 'xn--wgv71a', 'Non-ASCII domain name' );
}


{				## compatibility with defunct Net::DNS::ZoneFile 1.04 distro
	my $listref = Net::DNS::ZoneFile->read('zone8.txt');
	ok( scalar(@$listref), 'read entire zone file' );
}


{
	my $listref = Net::DNS::ZoneFile->read( 'zone8.txt', '.' );
	ok( scalar(@$listref), 'read zone file via path' );
}


{
	my $string  = "";
	my $listref = Net::DNS::ZoneFile->parse( \$string );
	is( scalar(@$listref), 0, 'parse empty string' );
}


{
	my $string  = "a1.example A 192.0.2.1\na2.example A 192.0.2.2";
	my $listref = Net::DNS::ZoneFile->parse( \$string );	# this also tests readfh()
	is( scalar(@$listref), 2, 'parse RR string' );
}


exit;
