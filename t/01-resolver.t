# $Id: 01-resolver.t,v 1.2 1997/03/28 02:34:30 mfuhr Exp $

BEGIN { $| = 1; print "1..2\n"; }
END {print "not ok 1\n" unless $loaded;}

use Net::DNS;

$loaded = 1;
print "ok 1\n";

$res = new Net::DNS::Resolver;
print "not " unless defined($res);
print "ok 2\n";
