# $Id: 08-online.t,v 1.4 2002/08/15 15:44:53 ctriv Exp $

use Test::More tests => 50;
use strict;

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
	skip 'Online testing disabled.', 49
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
}
		
