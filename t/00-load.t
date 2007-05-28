# $Id$ -*-perl-*-


use Test::More tests => 79;
use strict;

BEGIN { 
    use_ok('Net::DNS'); 
    use_ok('Net::DNS::Resolver::Recurse');
    use_ok('Net::DNS::Nameserver');
    use_ok('Net::DNS::Resolver::Cygwin');  
    # can't test windows, has registry stuff
}


sub is_rr_loaded {
	my ($rr) = @_;
	
	return $INC{"Net/DNS/RR/$rr.pm"} ? 1 : 0;
}

# Skip all Net::DNS::SEC related records.
my %skip = map { $_ => 1 } qw(SIG NXT KEY DS NSEC RRSIG DNSKEY DLV NSEC3 NSEC3PARAM);

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
	my $version;
	eval { $class = Net::DNS::RR->_get_subclass($rr); };

	diag($@) if $@;

	ok(is_rr_loaded($rr), "$class loaded");
	next unless $?;
	
	# Print version of the loaded module
	{
	    no strict 'refs';
	    $version = ${"${class}::VERSION"};
	    use strict;
	}
	diag $class.": ". $version; # e.g. 3.05 on my machine





}

#
# Did we get things imported correctly?
#
{ 	
	no strict 'refs';
	foreach my $sym (@Net::DNS::EXPORT) {
		ok(defined &{$sym}, "$sym is imported");
	}
}
			
