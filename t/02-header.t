# $Id: 02-header.t,v 1.2 1997/03/28 02:34:43 mfuhr Exp $

BEGIN { $| = 1; print "1..2\n"; }
END {print "not ok 1\n" unless $loaded;}

use Net::DNS;

$loaded = 1;
print "ok 1\n";

$header = new Net::DNS::Header;
print "not " unless defined($header);
print "ok 2\n";
