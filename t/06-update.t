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
	my $rr = yxrrset("$name $class $type");

	ok( $rr, 'yxrrset() returned RR' );			#7
	is( $rr->name,	$name, 'yxrrset - right name' );
	is( $rr->ttl,	0,     'yxrrset - right TTL' );
	is( $rr->class, 'ANY', 'yxrrset - right class' );
	is( $rr->type,	$type, 'yxrrset - right type' );
	ok( is_empty( $rr->rdatastr ), 'yxrrset - data empty' );
}

#------------------------------------------------------------------------------
# RRset exists (value-dependent).
#------------------------------------------------------------------------------

{
	my $rr = yxrrset("$name $class $type $rdata");

	ok( $rr, 'yxrrset() returned RR' );			#13
	is( $rr->name,	   $name,  'yxrrset - right name' );
	is( $rr->ttl,	   0,	   'yxrrset - right TTL' );
	is( $rr->class,	   $class, 'yxrrset - right class' );
	is( $rr->type,	   $type,  'yxrrset - right type' );
	is( $rr->rdatastr, $rdata, 'yxrrset - right data' );
}


#------------------------------------------------------------------------------
# RRset does not exist.
#------------------------------------------------------------------------------

{
	my $rr = nxrrset("$name $class $type");

	ok( $rr, 'nxrrset() returned RR' );			#19
	is( $rr->name,	$name,	'nxrrset - right name' );
	is( $rr->ttl,	0,	'nxrrset - right ttl' );
	is( $rr->class, 'NONE', 'nxrrset - right class' );
	is( $rr->type,	$type,	'nxrrset - right type' );
	ok( is_empty( $rr->rdatastr ), 'nxrrset - data empty' );
}


#------------------------------------------------------------------------------
# Name is in use.
#------------------------------------------------------------------------------

{
	my $rr = yxdomain("$name $class");

	ok( $rr, 'yxdomain() returned RR' );			#25
	is( $rr->name,	$name, 'yxdomain - right name' );
	is( $rr->ttl,	0,     'yxdomain - right ttl' );
	is( $rr->class, 'ANY', 'yxdomain - right class' );
	is( $rr->type,	'ANY', 'yxdomain - right type' );
	ok( is_empty( $rr->rdatastr ), 'yxdomain - data empty' );
}


#------------------------------------------------------------------------------
# Name is not in use.
#------------------------------------------------------------------------------

{
	my $rr = nxdomain("$name $class");

	ok( $rr, 'nxdomain() returned RR' );			#31
	is( $rr->name,	$name,	'nxdomain - right name' );
	is( $rr->ttl,	0,	'nxdomain - right ttl' );
	is( $rr->class, 'NONE', 'nxdomain - right class' );
	is( $rr->type,	'ANY',	'nxdomain - right type' );
	ok( is_empty( $rr->rdatastr ), 'nxdomain - data empty' );
}


#------------------------------------------------------------------------------
# Add to an RRset.
#------------------------------------------------------------------------------

{
	my $rr = rr_add("$name $ttl $class $type $rdata");

	ok( $rr, 'rr_add() returned RR' );			#37
	is( $rr->name,	   $name,  'rr_add - right name' );
	is( $rr->ttl,	   $ttl,   'rr_add - right ttl' );
	is( $rr->class,	   $class, 'rr_add - right class' );
	is( $rr->type,	   $type,  'rr_add - right type' );
	is( $rr->rdatastr, $rdata, 'rr_add - right data' );
}


#------------------------------------------------------------------------------
# Delete an RRset.
#------------------------------------------------------------------------------

{
	my $rr = rr_del("$name $class $type");

	ok( $rr, 'rr_del() returned RR' );			#43
	is( $rr->name,	$name, 'rr_del - right name' );
	is( $rr->ttl,	0,     'rr_del - right ttl' );
	is( $rr->class, 'ANY', 'rr_del - right class' );
	is( $rr->type,	$type, 'rr_del - right type' );
	ok( is_empty( $rr->rdatastr ), 'rr_del - data empty' );
}

#------------------------------------------------------------------------------
# Delete All RRsets From A Name.
#------------------------------------------------------------------------------

{
	my $rr = rr_del("$name");

	ok( $rr, 'rr_del() returned RR' );			#49
	is( $rr->name,	$name, 'rr_del - right name' );
	is( $rr->ttl,	0,     'rr_del - right ttl' );
	is( $rr->class, 'ANY', 'rr_del - right class' );
	is( $rr->type,	'ANY', 'rr_del - right type' );
	ok( is_empty( $rr->rdatastr ), 'rr_del - data empty' );
}

#------------------------------------------------------------------------------
# Delete All RRsets From A Name (with gratuitous class name).
#------------------------------------------------------------------------------

{
	my $rr = rr_del("$name $class");

	ok( $rr, 'nxdomain() returned RR' );			#55
	is( $rr->name,	$name, 'nxdomain - right name' );
	is( $rr->ttl,	0,     'nxdomain - right ttl' );
	is( $rr->class, 'ANY', 'nxdomain - right class' );
	is( $rr->type,	'ANY', 'nxdomain - right type' );
	ok( is_empty( $rr->rdatastr ), 'nxdomain - data empty' );
}

#------------------------------------------------------------------------------
# Delete An RR From An RRset.
#------------------------------------------------------------------------------

{
	my $rr = rr_del("$name $class $type $rdata");

	ok( $rr, 'rr_del() returned RR' );			#61
	is( $rr->name,	   $name,  'rr_del - right name' );
	is( $rr->ttl,	   0,	   'rr_del - right ttl' );
	is( $rr->class,	   'NONE', 'rr_del - right class' );
	is( $rr->type,	   $type,  'rr_del - right type' );
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

