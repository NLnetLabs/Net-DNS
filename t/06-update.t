# $Id: 06-update.t,v 1.2 1997/07/05 17:47:06 mfuhr Exp $

BEGIN { $| = 1; print "1..65\n"; }
END {print "not ok 1\n" unless $loaded;}

use Net::DNS;

$loaded = 1;
print "ok 1\n";

sub is_empty {
	my $string = shift;
	return ($string eq "; no data" || $string eq "; rdlength = 0");
}

#------------------------------------------------------------------------------
# Canned data.
#------------------------------------------------------------------------------

$zone	= "bar.com";
$name	= "foo.bar.com";
$class	= "HS";
$class2 = "CH";
$type	= "A";
$ttl	= 43200;
$rdata	= "10.1.2.3";

#------------------------------------------------------------------------------
# Packet creation.
#------------------------------------------------------------------------------

$packet = new Net::DNS::Update($zone, $class);
print "not " unless $packet;
print "ok 2\n";

print "not " unless $packet->header->opcode eq "UPDATE";
print "ok 3\n";

print "not " unless ($packet->zone)[0]->zname eq $zone;
print "ok 4\n";

print "not " unless ($packet->zone)[0]->zclass eq $class;
print "ok 5\n";

print "not " unless ($packet->zone)[0]->ztype eq "SOA";
print "ok 6\n";

#------------------------------------------------------------------------------
# RRset exists (value-independent).
#------------------------------------------------------------------------------

$rr = yxrrset("$name $class $type");
print "not " unless $rr;
print "ok 7\n";

print "not " unless $rr->name eq $name;
print "ok 8\n";

print "not " unless $rr->ttl == 0;
print "ok 9\n";

print "not " unless $rr->class eq "ANY";
print "ok 10\n";

print "not " unless $rr->type eq $type;
print "ok 11\n";

print "not " unless is_empty($rr->rdatastr);
print "ok 12\n";

#------------------------------------------------------------------------------
# RRset exists (value-dependent).
#------------------------------------------------------------------------------

$rr = yxrrset("$name $class $type $rdata");
print "not " unless $rr;
print "ok 13\n";

print "not " unless $rr->name eq $name;
print "ok 14\n";

print "not " unless $rr->ttl == 0;
print "ok 15\n";

print "not " unless $rr->class eq $class;
print "ok 16\n";

print "not " unless $rr->type eq $type;
print "ok 17\n";

print "not " unless $rr->rdatastr eq $rdata;
print "ok 18\n";

#------------------------------------------------------------------------------
# RRset does not exist.
#------------------------------------------------------------------------------

$rr = nxrrset("$name $class $type");
print "not " unless $rr;
print "ok 19\n";

print "not " unless $rr->name eq $name;
print "ok 20\n";

print "not " unless $rr->ttl == 0;
print "ok 21\n";

print "not " unless $rr->class eq "NONE";
print "ok 22\n";

print "not " unless $rr->type eq $type;
print "ok 23\n";

print "not " unless is_empty($rr->rdatastr);
print "ok 24\n";

#------------------------------------------------------------------------------
# Name is in use.
#------------------------------------------------------------------------------

$rr = yxdomain("$name $class");
print "not " unless $rr;
print "ok 25\n";

print "not " unless $rr->name eq $name;
print "ok 26\n";

print "not " unless $rr->ttl == 0;
print "ok 27\n";

print "not " unless $rr->class eq "ANY";
print "ok 28\n";

print "not " unless $rr->type eq "ANY";
print "ok 29\n";

print "not " unless is_empty($rr->rdatastr);
print "ok 30\n";

#------------------------------------------------------------------------------
# Name is not in use.
#------------------------------------------------------------------------------

$rr = nxdomain("$name $class");
print "not " unless $rr;
print "ok 31\n";

print "not " unless $rr->name eq $name;
print "ok 32\n";

print "not " unless $rr->ttl == 0;
print "ok 33\n";

print "not " unless $rr->class eq "NONE";
print "ok 34\n";

print "not " unless $rr->type eq "ANY";
print "ok 35\n";

print "not " unless is_empty($rr->rdatastr);
print "ok 36\n";

#------------------------------------------------------------------------------
# Add to an RRset.
#------------------------------------------------------------------------------

$rr = rr_add("$name $ttl $class $type $rdata");
print "not " unless $rr;
print "ok 37\n";

print "not " unless $rr->name eq $name;
print "ok 38\n";

print "not " unless $rr->ttl == $ttl;
print "ok 39\n";

print "not " unless $rr->class eq $class;
print "ok 40\n";

print "not " unless $rr->type eq $type;
print "ok 41\n";

print "not " unless $rr->rdatastr eq $rdata;
print "ok 42\n";

#------------------------------------------------------------------------------
# Delete an RRset.
#------------------------------------------------------------------------------

$rr = rr_del("$name $class $type");
print "not " unless $rr;
print "ok 43\n";

print "not " unless $rr->name eq $name;
print "ok 44\n";

print "not " unless $rr->ttl == 0;
print "ok 45\n";

print "not " unless $rr->class eq "ANY";
print "ok 46\n";

print "not " unless $rr->type eq $type;
print "ok 47\n";

print "not " unless is_empty($rr->rdatastr);
print "ok 48\n";

#------------------------------------------------------------------------------
# Delete All RRsets From A Name.
#------------------------------------------------------------------------------

$rr = rr_del("$name $class");
print "not " unless $rr;
print "ok 49\n";

print "not " unless $rr->name eq $name;
print "ok 50\n";

print "not " unless $rr->ttl == 0;
print "ok 51\n";

print "not " unless $rr->class eq "ANY";
print "ok 52\n";

print "not " unless $rr->type eq "ANY";
print "ok 53\n";

print "not " unless is_empty($rr->rdatastr);
print "ok 54\n";

#------------------------------------------------------------------------------
# Delete An RR From An RRset.
#------------------------------------------------------------------------------

$rr = rr_del("$name $class $type $rdata");
print "not " unless $rr;
print "ok 55\n";

print "not " unless $rr->name eq $name;
print "ok 56\n";

print "not " unless $rr->ttl == 0;
print "ok 57\n";

print "not " unless $rr->class eq "NONE";
print "ok 58\n";

print "not " unless $rr->type eq $type;
print "ok 59\n";

print "not " unless $rr->rdatastr eq $rdata;
print "ok 60\n";

#------------------------------------------------------------------------------
# Make sure RRs in an update packet have the same class as the zone, unless
# the class is NONE or ANY.
#------------------------------------------------------------------------------

$packet = new Net::DNS::Update($zone, $class);
print "not " unless $packet;
print "ok 61\n";

$rr = yxrrset("$name $class $type $rdata");
$packet->push("pre", $rr);
print "not " unless ($packet->pre)[0]->class eq $class;
print "ok 62\n";

$rr = yxrrset("$name $class2 $type $rdata");
$packet->push("pre", $rr);
print "not " unless ($packet->pre)[1]->class eq $class;
print "ok 63\n";

$rr = yxrrset("$name $class2 $type");
$packet->push("pre", $rr);
print "not " unless ($packet->pre)[2]->class eq "ANY";
print "ok 64\n";

$rr = nxrrset("$name $class2 $type");
$packet->push("pre", $rr);
print "not " unless ($packet->pre)[3]->class eq "NONE";
print "ok 65\n";
