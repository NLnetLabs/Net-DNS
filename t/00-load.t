# $Id: 00-load.t,v 1.2 2003/01/05 21:28:04 ctriv Exp $


use Test::More tests => 64;
use strict;

BEGIN { 
    use_ok('Net::DNS'); 
    use_ok('Net::DNS::Resolver::Recurse');
}


sub is_rr_loaded {
	my ($rr) = @_;
	
	return $INC{"Net/DNS/RR/$rr.pm"} ? 1 : 0;
}


#
# Make sure that we haven't loaded any of the RR classes yet.
#
foreach my $rr (keys %Net::DNS::RR::RR) {
	ok(!is_rr_loaded($rr), "Net::DNS::RR::$rr is not loaded");
}

#
# Check that we can load all the RR modules.
#
foreach my $rr (keys %Net::DNS::RR::RR) {
	my $class;
	eval { $class = Net::DNS::RR->_get_subclass($rr); };

	ok(is_rr_loaded($rr), "$class loaded");
}

