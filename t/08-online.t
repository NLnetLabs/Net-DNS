# $Id: 08-online.t,v 1.6 2003/01/05 21:28:04 ctriv Exp $

use Test::More;
use strict;

BEGIN {
	if (-e 't/online.enabled') {
		plan tests => 52;
	} else {
		plan skip_all => 'Online tests disabled.';
	}
}

BEGIN { use_ok('Net::DNS'); }

my $res = Net::DNS::Resolver->new;

my @rrs = (
	{
		type   		=> 'A',
		name   		=> 'a.t.net-dns.org',
		address 	=> '10.0.1.128',
	},
	{
		type		=> 'MX',
		name		=> 'mx.t.net-dns.org',
		exchange	=> 'a.t.net-dns.org',
		preference 	=> 10,
	},
	{
		type		=> 'CNAME',
		name		=> 'cname.t.net-dns.org',
		cname		=> 'a.t.net-dns.org',
	},
	{
		type		=> 'TXT',
		name		=> 'txt.t.net-dns.org',
		txtdata		=> 'Net-DNS',
	},
		
);

SKIP: {
	skip 'Online testing disabled.', 51
		unless -e 't/online.enabled';
		

	foreach my $data (@rrs) {
		my $packet = $res->send($data->{'name'}, $data->{'type'}, 'IN');
		
		ok($packet, "Got an answer for $data->{name} IN $data->{type}");
		is($packet->header->qdcount, 1, 'Only one question');
		is($packet->header->ancount, 1, 'Got single answer');
		
		my $question = ($packet->question)[0];
		my $answer   = ($packet->answer)[0];
		
		ok($question,                           'Got question'            );
		is($question->qname,  $data->{'name'},  'Question has right name' );
		is($question->qtype,  $data->{'type'},  'Question has right type' );
		is($question->qclass, 'IN',             'Question has right class');
		
		ok($answer,                                                       );
		is($answer->class,    'IN',             'Class correct'           );

		
		foreach my $meth (keys %{$data}) {
			is($answer->$meth(), $data->{$meth}, "$meth correct");
		}
	}
	
	my $check_serv_res = Net::DNS::Resolver->new;
	
	$check_serv_res->nameservers('a.t.net-dns.org');
	my $ip = ($check_serv_res->nameservers)[0];
	is($ip, '10.0.1.128', 'Nameservers() looks up IP.');
	
	$check_serv_res->nameservers('cname.t.net-dns.org');
	$ip = ($check_serv_res->nameservers)[0];
	is($ip, '10.0.1.128', 'Nameservers() looks up cname.');
	
	
}
		
