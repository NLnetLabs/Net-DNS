# $Id: 00-load.t,v 1.3 2003/01/07 23:27:41 ctriv Exp $


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

my %skip = map { $_ => 1 } qw(SIG NXT KEY DS);

my @rrs = grep { !$skip{$_} } keys %Net::DNS::RR::RR;



#
# Make sure that we haven't loaded any of the RR classes yet.
#
foreach my $rr (@rrs) {
	ok(!is_rr_loaded($rr), "Net::DNS::RR::$rr is not loaded");
}

#
# Check that we can load all the RR modules.
#
foreach my $rr (@rrs) {
	my $class;
	eval { $class = Net::DNS::RR->_get_subclass($rr); };

	ok(is_rr_loaded($rr), "$class loaded");
}

