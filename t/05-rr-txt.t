# $Id: 05-rr-txt.t,v 1.1 2003/03/06 18:10:30 ctriv Exp $

use Test::More tests => 32;
use strict;
use vars qw( $uut @list );


BEGIN { use_ok('Net::DNS'); }

#------------------------------------------------------------------------------
# Canned data.
#------------------------------------------------------------------------------

my $name			= 'foo.example.com';
my $class			= 'IN';
my $type			= 'TXT';
my $ttl				= 43201;

my $rr_base	= join(' ', $name, $ttl, $class, $type, "    " );

#Stimulus, expected response, and test name:

my @Testlist =	(
		    {	# 2-5
			stim		=>	q|""|,
			rdatastr	=>	q|""|,
			char_str_list_r	=>	['',],
			descr		=>	'Double-quoted null string',
			},
		    {	# 6-9
			stim		=>	q|''|,
			rdatastr	=>	q|""|,
			char_str_list_r	=>	['',],
			descr		=>	'Single-quoted null string',
			},
		    {	# 10-13
			stim		=>	qq|" \t"|,
			rdatastr	=>	qq|" \t"|,
			char_str_list_r	=>	[ qq| \t|, ],
			descr		=>	'Double-quoted whitespace string',
			},
		    {	# 14-17
			stim		=>	q|noquotes|,
			rdatastr	=>	q|"noquotes"|,
			char_str_list_r	=>	[ q|noquotes|, ],
			descr		=>	'unquoted single string',
			},
		    {	# 18-21
			stim		=>	q|"yes_quotes"|,
			rdatastr	=>	q|"yes_quotes"|,
			char_str_list_r	=>	[ q|yes_quotes|, ],
			descr		=>	'Double-quoted single string',
			},
		    {	# 22-25
			stim		=>	q|"escaped \" quote"|,
			rdatastr	=>	q|"escaped \" quote"|,
			char_str_list_r	=>	[ q|escaped " quote|, ],
			descr		=>	'Quoted, escaped double-quote',
			},
		    {	# 26-29
			stim		=>	q|two tokens|,
			rdatastr	=>	q|"two" "tokens"|,
			char_str_list_r	=>	[ q|two|, q|tokens|, ],
			descr		=>	'Two unquoted strings',
			},
		);

#------------------------------------------------------------------------------
# Run the tests
#------------------------------------------------------------------------------

foreach my $test_hr ( @Testlist ) {
    ok( $uut = Net::DNS::RR->new($rr_base . $test_hr->{'stim'}), 	
	$test_hr->{'descr'} . " -- Stimulus " ); 
    ok( $uut->rdatastr() eq $test_hr->{'rdatastr'}, 			
	$test_hr->{'descr'} . " -- Response ( rdatastr ) " ); 
    ok( defined ( @list = $uut->char_str_list() ), 
	$test_hr->{'descr'} . " -- Response ( defined char_str_list ) " );
    ok( eq_array( \@list, $test_hr->{'char_str_list_r'}) , 
	$test_hr->{'descr'} . " -- char_str_list equality"  ) ;		
}

my $string1 = q|no|;
my $string2 = q|quotes|;

my $rdata = pack("C", length $string1) . $string1;
$rdata .= pack("C", length $string2) . $string2;

# RR->new_from_hash() drops stuff straight into the hash and 
# re-blesses it, breaking encapsulation.

my %base_hash = (
	Name		=> $name,
	TTL		=> $ttl,
	Class		=> $class,
	Type		=> $type,
	);

my %work_hash = %base_hash;

# Don't break RR->new_from_hash (e.i. "See the manual pages for each RR 
# type to see what fields the type requires.").

$work_hash{'txtdata'} = q|no quotes|;	

ok( $uut = Net::DNS::RR->new(%work_hash), 		# 30
    "RR->new_from_hash with txtdata -- Stimulus");
ok( $uut->rdatastr() eq q|"no" "quotes"|, 		# 31
    "RR->new_from_hash with txtdata -- Response (rdatastr())");

ok( $uut->rr_rdata() eq $rdata , "TXT->rr_rdata" );	# 32

sleep 0;

