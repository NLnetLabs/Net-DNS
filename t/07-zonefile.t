# $Id$	-*-perl-*-

use strict;
use FileHandle;

use Test::More tests => 57;

use constant UTF8 => eval {
	require Encode;						# expect this to fail pre-5.8.0
	die if Encode::decode_utf8( chr(91) ) ne '[';		# not UTF-EBCDIC  [see UTR#16 3.6]
	Encode::find_encoding('UTF8');
} || 0;

use constant LIBIDN => eval {
	require Net::LibIDN;					# optional IDN support
	UTF8 && Net::LibIDN::idn_to_ascii( pack( 'U*', 20013, 22269 ), 'utf-8' ) eq 'xn--fiqs8s';
} || 0;


BEGIN {
	use_ok('Net::DNS::ZoneFile');
}


my $seq;

sub source {				## zone file builder
	my $text = shift;
	my @args = @_;

	my $tag	 = ++$seq;
	my $file = "zone$tag.txt";

	my $handle = new FileHandle( $file, '>' );		# create test file
	die "Failed to create $file" unless $handle;
	eval{ binmode($handle) };				# suppress encoding layer

	print $handle $text;
	close $handle;

	return new Net::DNS::ZoneFile( $file, @args );
}


{				## public methods
	my $zonefile = source('');
	isa_ok( $zonefile, 'Net::DNS::ZoneFile', 'new ZoneFile object' );

	ok( defined $zonefile->name,   'zonefile->name always defined' );
	ok( defined $zonefile->line,   'zonefile->line always defined' );
	ok( defined $zonefile->origin, 'zonefile->origin always defined' );
	ok( defined $zonefile->ttl,    'zonefile->ttl always defined' );
	my @rr = $zonefile->read;
	is( scalar(@rr),     0, 'zonefile->read to end of file' );
	is( $zonefile->line, 0, 'zonefile->line zero if file empty' );

	is( $zonefile->origin, '.', 'zonefile->origin defaults to DNS root' );
}


{				## initial origin
	my $tld = 'test';
	my $absolute = source( '', "$tld." );
	is( $absolute->origin, "$tld.", 'new ZoneFile with absolute origin' );

	my $relative = source( '', "$tld" );
	is( $relative->origin, "$tld.", 'new ZoneFile->origin always absolute' );
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


my $zonefile;
{				## $ORIGIN directive
	my $nested = source <<'EOF';
nested	NULL
EOF

	my $origin = 'example.com';
	my $ORIGIN = '$ORIGIN';
	my $inner = join ' ', '$INCLUDE', $nested->name;
	my $include = source <<"EOF";
$ORIGIN $origin
@	NS	host
$inner 
@	NULL
$ORIGIN relative
@	NULL
EOF

	my $outer  = join ' ', '$INCLUDE', $include->name;
	$zonefile = source <<"EOF";
$outer 
outer	NULL
EOF

	my $ns = $zonefile->read;
	is( $ns->name,	  $origin,	  '@	NS	has expected name' );
	is( $ns->nsdname, "host.$origin", '@	NS	has expected rdata' );

	my $rr = $zonefile->read;
	my $expect = join '.', 'nested', $origin;
	is( $rr->name, $expect, 'scope of $ORIGIN encompasses nested $INCLUDE' );

	is( $zonefile->read->name, $origin, 'scope of $ORIGIN continues after $INCLUDE' );

	is( $zonefile->read->name, "relative.$origin", '$ORIGIN can be relative to current $ORIGIN' );

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


{
	my $zonefile = source <<'EOF';
$TTL 1234
$ORIGIN example.
hosta	A	192.0.2.1
	MX	10 hosta
	TXT	( multiline	; interspersed ( mischievously )
		resource	; with	( confusing )
		record	)	; comments
	TXT	string
EOF
	is( $zonefile->read->name, 'hosta.example', 'name of simple RR as expected' );
	is( $zonefile->read->name, 'hosta.example', 'name of simple RR propagated from previous RR' );
	my $multilineRR = $zonefile->read;
	is( $multilineRR->name, 'hosta.example', 'name of multiline RR propagated from previous RR' );
	is( $multilineRR->txtdata, 'multiline resource record', 'multiline RR correctly reassembled' );
	is( $zonefile->read->name, 'hosta.example', 'name of following RR as expected' );
}


{				## compatibility with defunct Net::DNS::ZoneFile 1.04 distro
	my $listref = Net::DNS::ZoneFile->read( $zonefile->name );
	ok( scalar(@$listref), 'read entire zone file' );
}


{
	my $listref = Net::DNS::ZoneFile->read( $zonefile->name, '.' );
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


SKIP: {				## Non-ASCII zone content
	skip( 'Unicode/UTF-8 not supported', 3 ) unless UTF8;
	skip( 'Non-ASCII file encoding not supported', 3 ) if eval{ $] < 5.010 };

	my $greek = pack 'C*', 103, 114, 9, 84, 88, 84, 9, 229, 224, 241, 231, 234, 225, 10;
	my $file1 = source($greek);
	my $fh1   = new FileHandle( $file1->name, '<:encoding(ISO8859-7)' );	# Greek
	my $zone1 = new Net::DNS::ZoneFile($fh1);
	my $txtgr = $zone1->read;
	my $text  = pack 'U*', 949, 944, 961, 951, 954, 945;
	is( $txtgr->txtdata, $text , 'ISO8859-7 TXT rdata' );

	eval{ binmode(DATA) };					# suppress encoding layer
	my $jptxt = <DATA>;
	my $file2 = source($jptxt);
	my $fh2   = new FileHandle( $file2->name, '<:utf8' );	# UTF-8 character encoding
	my $zone2 = new Net::DNS::ZoneFile($fh2);
	my $txtrr = $zone2->read;				# TXT RR with kanji RDATA
	my @rdata = $txtrr->txtdata;
	my $rdata = $txtrr->txtdata;
	is( length($rdata), 12, 'Unicode/UTF-8 TXT rdata' );
	is( scalar(@rdata), 1,  'Unicode/UTF-8 TXT contiguous' );

	skip( 'Non-ASCII domain - Net::LibIDN not available', 1 ) unless LIBIDN;

	my $kanji = <DATA>;
	my $zone3 = source($kanji);
	my $nextr = $zone3->read;				# NULL RR with kanji owner name
	is( $nextr->name, 'xn--wgv71a', 'Unicode/UTF-8 domain name' );
}


exit;

__END__
jp	TXT	古池や　蛙飛込む　水の音		; Unicode text string
日本	NULL						; Unicode domain name

