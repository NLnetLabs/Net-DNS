# $Id$  -*-perl-*-

use Test::More tests => 72;
use strict;


BEGIN { use_ok('Net::DNS'); }					#1


sub is_empty {
	local $_ = shift;

	return 0 unless defined $_;
	return 1 unless length $_;

	return 1 if /\\# 0/;
	return 1 if /; no data/;
	return 1 if /; rdlength = 0/;
	return 0;
}


#------------------------------------------------------------------------------
# Canned data.
#------------------------------------------------------------------------------

my $zone   = "example.com";
my $name   = "foo.example.com";
my $class  = "HS";
my $class2 = "CH";
my $type   = "A";
my $ttl	   = 43200;
my $rdata  = "10.1.2.3";

#------------------------------------------------------------------------------
# Packet creation.
#------------------------------------------------------------------------------

{
	my $packet = Net::DNS::Update->new( $zone, $class );
	my ($z) = ( $packet->zone )[0];

	ok( $packet, 'new() returned packet' );			#2
	is( $packet->header->opcode, 'UPDATE', 'header opcode correct' );
	is( $z->zname,		     $zone,    'zname correct' );
	is( $z->zclass,		     $class,   'zclass correct' );
	is( $z->ztype,		     'SOA',    'ztype correct' );
}


#------------------------------------------------------------------------------
# RRset exists (value-independent).
#------------------------------------------------------------------------------

{
	my $arg = "$name $ttl $class $type";
	my $rr	= yxrrset($arg);

	ok( $rr, "yxrrset($arg)" );				#7
	is( $rr->name,	$name, 'yxrrset - right name' );
	is( $rr->ttl,	0,     'yxrrset - ttl	0' );
	is( $rr->class, 'ANY', 'yxrrset - class ANY' );
	is( $rr->type,	$type, "yxrrset - type	$type" );
	ok( is_empty( $rr->rdatastr ), 'yxrrset - data empty' );
}

#------------------------------------------------------------------------------
# RRset exists (value-dependent).
#------------------------------------------------------------------------------

{
	my $arg = "$name $ttl $class $type $rdata";
	my $rr	= yxrrset($arg);

	ok( $rr, "yxrrset($arg)" );				#13
	is( $rr->name,	   $name,  'yxrrset - right name' );
	is( $rr->ttl,	   0,	   'yxrrset - ttl   0' );
	is( $rr->class,	   $class, "yxrrset - class $class" );
	is( $rr->type,	   $type,  "yxrrset - type  $type" );
	is( $rr->rdatastr, $rdata, 'yxrrset - right data' );
}


#------------------------------------------------------------------------------
# RRset does not exist.
#------------------------------------------------------------------------------

{
	my $arg = "$name $ttl $class $type $rdata";
	my $rr	= nxrrset($arg);

	ok( $rr, "nxrrset($arg)" );				#19
	is( $rr->name,	$name,	'nxrrset - right name' );
	is( $rr->ttl,	0,	'nxrrset - ttl	 0' );
	is( $rr->class, 'NONE', 'nxrrset - class NONE' );
	is( $rr->type,	$type,	"nxrrset - type	 $type" );
	ok( is_empty( $rr->rdatastr ), 'nxrrset - data empty' );
}


#------------------------------------------------------------------------------
# Name is in use.
#------------------------------------------------------------------------------

{
	my $arg = "$name $class";
	my $rr	= yxrrset($arg);

	ok( $rr, "yxrrset($arg)" );				#25
	is( $rr->name,	$name, 'yxdomain - right name' );
	is( $rr->ttl,	0,     'yxdomain - ttl	 0' );
	is( $rr->class, 'ANY', 'yxdomain - class ANY' );
	is( $rr->type,	'ANY', 'yxdomain - type	 ANY' );
	ok( is_empty( $rr->rdatastr ), 'yxdomain - data empty' );
}


#------------------------------------------------------------------------------
# Name is not in use.
#------------------------------------------------------------------------------

{
	my $arg = "$name $class";
	my $rr	= nxdomain($arg);

	ok( $rr, "nxdomain($arg)" );				#31
	is( $rr->name,	$name,	'nxdomain - right name' );
	is( $rr->ttl,	0,	'nxdomain - ttl	  0' );
	is( $rr->class, 'NONE', 'nxdomain - class NONE' );
	is( $rr->type,	'ANY',	'nxdomain - type  ANY' );
	ok( is_empty( $rr->rdatastr ), 'nxdomain - data empty' );
}


#------------------------------------------------------------------------------
# Add to an RRset.
#------------------------------------------------------------------------------

{
	my $arg = "$name $ttl $class $type $rdata";
	my $rr	= rr_add($arg);

	ok( $rr, "rr_add($arg)" );				#37
	is( $rr->name,	   $name,  'rr_add - right name' );
	is( $rr->ttl,	   $ttl,   "rr_add - ttl   $ttl" );
	is( $rr->class,	   $class, "rr_add - class $class" );
	is( $rr->type,	   $type,  "rr_add - type  $type" );
	is( $rr->rdatastr, $rdata, 'rr_add - right data' );
}


#------------------------------------------------------------------------------
# Delete an RRset.
#------------------------------------------------------------------------------

{
	my $arg = "$name $class $type";
	my $rr	= rr_del($arg);

	ok( $rr, "rr_del($arg)" );				#43
	is( $rr->name,	$name, 'rr_del - right name' );
	is( $rr->ttl,	0,     'rr_del - ttl   0' );
	is( $rr->class, 'ANY', 'rr_del - class ANY' );
	is( $rr->type,	$type, "rr_del - type  $type" );
	ok( is_empty( $rr->rdatastr ), 'rr_del - data empty' );
}

#------------------------------------------------------------------------------
# Delete All RRsets From A Name.
#------------------------------------------------------------------------------

{
	my $arg = "$name";
	my $rr	= rr_del($arg);

	ok( $rr, "rr_del($arg)" );				#49
	is( $rr->name,	$name, 'rr_del - right name' );
	is( $rr->ttl,	0,     'rr_del - ttl   0' );
	is( $rr->class, 'ANY', 'rr_del - class ANY' );
	is( $rr->type,	'ANY', 'rr_del - type  ANY' );
	ok( is_empty( $rr->rdatastr ), 'rr_del - data empty' );
}

#------------------------------------------------------------------------------
# Delete All RRsets From A Name (with gratuitous class name).
#------------------------------------------------------------------------------

{
	my $arg = "$name $class";
	my $rr	= rr_del($arg);

	ok( $rr, "rr_del($arg)" );				#55
	is( $rr->name,	$name, 'rr_del - right name' );
	is( $rr->ttl,	0,     'rr_del - ttl   0' );
	is( $rr->class, 'ANY', 'rr_del - class ANY' );
	is( $rr->type,	'ANY', 'rr_del - type  ANY' );
	ok( is_empty( $rr->rdatastr ), 'rr_del - data empty' );
}

#------------------------------------------------------------------------------
# Delete An RR From An RRset.
#------------------------------------------------------------------------------

{
	my $arg = "$name $class $type $rdata";
	my $rr	= rr_del($arg);

	ok( $rr, "rr_del($arg)" );				#61
	is( $rr->name,	   $name,  'rr_del - right name' );
	is( $rr->ttl,	   0,	   'rr_del - ttl   0' );
	is( $rr->class,	   'NONE', 'rr_del - class NONE' );
	is( $rr->type,	   $type,  "rr_del - type  $type" );
	is( $rr->rdatastr, $rdata, 'rr_del - right data' );
}


#------------------------------------------------------------------------------
# Make sure RRs in an update packet have the same class as the zone, unless
# the class is NONE or ANY.
#------------------------------------------------------------------------------

{
	my $packet = Net::DNS::Update->new( $zone, $class );
	ok( $packet, 'packet created' );			#67

	$packet->push( "pre", yxrrset("$name $class $type $rdata") );
	$packet->push( "pre", yxrrset("$name $class2 $type $rdata") );
	$packet->push( "pre", yxrrset("$name $class2 $type") );
	$packet->push( "pre", nxrrset("$name $class2 $type") );

	my @pre = $packet->pre;

	is( scalar(@pre),   4,	    '"pre" length correct' );	#68
	is( $pre[0]->class, $class, 'first class right' );
	is( $pre[1]->class, $class, 'second class right' );
	is( $pre[2]->class, 'ANY',  'third class right' );
	is( $pre[3]->class, 'NONE', 'fourth class right' );
}

