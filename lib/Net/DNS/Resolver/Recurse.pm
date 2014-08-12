package Net::DNS::Resolver::Recurse;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


=head1 NAME

Net::DNS::Resolver::Recurse - Perform recursive DNS lookups


=head1 SYNOPSIS

    use Net::DNS::Resolver::Recurse;

    $resolver = new Net::DNS::Resolver::Recurse();

    $packet = $resolver->query ( 'www.example.com', 'A' );
    $packet = $resolver->search( 'www.example.com', 'A' );
    $packet = $resolver->send  ( 'www.example.com', 'A' );


=head1 DESCRIPTION

This module is a subclass of Net::DNS::Resolver.

=cut


use strict;
use base qw(Net::DNS::Resolver);


=head1 METHODS

This module inherits almost all the methods from Net::DNS::Resolver.
Additional module-specific methods are described below.


=head2 hints

This method specifies a list of the IP addresses used to locate
the authoritative name servers for the root (.) zone.

    $resolver->hints(@ip);

If no hints are passed, the default nameserver is used to discover
the addresses of the root nameservers.

If the default nameserver not been configured correctly,
or at all, a built-in list of IP addresses is used.

=cut

my @hints;
my $root;

sub hints {
	my $self = shift;

	@hints = @_ if scalar @_;
	return @hints;
}


=head2 query, search, send

The query(), search() and send() methods produce the same result
as their counterparts in Net::DNS::Resolver.

    $packet = $resolver->send( 'www.example.com.', 'A' );

Server-side recursion is suppressed by clearing the recurse flag
in the packet and recursive name resolution is performed explicitly.

The query() and search() methods are inherited from Net::DNS::Resolver
and invoke send() indirectly.

=cut

sub send {
	return &Net::DNS::Resolver::Base::send if ref $_[1];	# send Net::DNS::Packet

	my $self = shift;
	my $res	 = bless {cache => {}, %$self}, ref($self);	# Note: cache discarded after query

	my $question = new Net::DNS::Question(@_);
	my $original = pop(@_);					# sneaky extra argument needed
	$original = $question unless ref($original);		# to preserve original request

	my ( $head, @tail ) = $question->{owner}->label;
	unless ($head) {
		return $root if $root;				# root servers cached indefinitely

		my $defres = new Net::DNS::Resolver( debug => 0 );
		$defres->nameservers( $res->hints ) || $defres->nameservers( $res->_hints );

		my $packet = $defres->send( '.', 'NS' );	# specified hint server
		$res->{callback}->($packet) if $res->{callback};
		my @auth = grep $_->type eq 'NS', $packet->answer, $packet->authority;
		my %auth = map { ( lc $_->nsdname => 1 ) } @auth;
		my @glue = grep $auth{lc $_->name}, $packet->additional;
		my %glue;
		push @{$glue{lc $_->name}}, $_->address foreach ( grep $_->type() eq 'A',    @glue );
		push @{$glue{lc $_->name}}, $_->address foreach ( grep $_->type() eq 'AAAA', @glue );
		my @ip = map @$_, values %glue;
		return $root = $packet if @ip && $packet->header->aa;

		$defres->nameservers(@ip);
		$defres->recurse(0);
		foreach my $ns ( map $_->nsdname, @auth ) {
			$defres->nameservers($ns) unless @ip;
			$packet = $defres->send( '.', 'NS' );	# authoritative root server
			$res->{callback}->($packet) if $res->{callback};
			my @auth = grep $_->type eq 'NS', $packet->answer, $packet->authority;
			my %auth = map { ( lc $_->nsdname => 1 ) } @auth;
			my @glue = grep $auth{lc $_->name}, $packet->additional;
			my @ip = grep $_->type eq 'A', @glue;
			push @ip, grep $_->type eq 'AAAA', @glue;
			return $root = $packet if @ip && @auth;
		}
		return $packet;
	}

	my $domain = $question->qtype ne 'ANY' ? $original->qname : join '.', @tail;
	my $nslist = $res->{cache}->{$domain} ||= [];
	if ( scalar @$nslist ) {
		print ";; using cached nameservers for $domain.\n" if $res->{debug};
	} else {
		my $packet = $res->send( $domain, 'ANY', 'ANY', $original ) || return;
		return $packet unless $packet->header->rcode eq 'NOERROR';

		my @answer = $packet->answer;			# return authoritative answer
		return $packet if $packet->header->aa && grep $_->name eq $original->qname, @answer;

		print ";; found nameservers for $domain.\n" if $res->{debug};
		my @auth = grep $_->type eq 'NS', $packet->answer, $packet->authority;
		my @name = map lc( $_->nsdname ), @auth;
		my %auth = map { ( $_ => 1 ) } @name;
		my @glue = grep $auth{lc $_->name}, $packet->additional;

		my %glue;
		push @{$glue{lc $_->name}}, $_->address foreach ( grep $_->type() eq 'A',    @glue );
		push @{$glue{lc $_->name}}, $_->address foreach ( grep $_->type() eq 'AAAA', @glue );
		@$nslist = values %glue;

		my @noglue = grep !$glue{$_}, @name;
		splice @noglue, 0, 0, splice( @noglue, int( rand scalar @noglue ) );
		push @$nslist, @noglue;
	}

	my $query = new Net::DNS::Packet();
	$query->push( question => $original );
	$res->recurse(0);

	my @a = grep ref($_), @$nslist;
	splice @a, 0, 0, splice( @a, int( rand scalar @a ) );	# cut deck

	while ( scalar @a ) {
		$res->nameservers( map @$_, @a );
		my $reply = $res->send($query) || last;
		$res->{callback}->($reply) if $res->{callback};
		last unless $reply->header->rcode eq 'NOERROR';
		return $reply;
	}

	foreach my $ns ( grep !ref($_), @$nslist ) {
		print ";; find missing glue for $domain. ($ns)\n" if $res->{debug};
		$res->empty_nameservers();
		my @ip = $res->nameservers($ns);
		next unless @ip;
		$ns = [@ip];					# substitute IP list in situ
		my $reply = $res->send($query) || next;
		$res->{callback}->($reply) if $res->{callback};
		next unless $reply->header->rcode eq 'NOERROR';
		return $reply;
	}
	return;
}

sub query_dorecursion { &send; }	## historical


=head2 callback

This method specifies a code reference to a subroutine,
which is then invoked at each stage of the recursive lookup.

For example to emulate dig's C<+trace> function:

    my $coderef = sub {
	my $packet = shift;

	$_->print for $packet->additional;

	printf ";; Received %d bytes from %s\n\n",
		$packet->answersize, $packet->answerfrom;
    };

    $resolver->callback($coderef);

The callback subroutine is not called
for queries for missing glue records.

=cut

sub callback {
	my ( $self, $sub ) = @_;

	$self->{callback} = $sub if $sub && UNIVERSAL::isa( $sub, 'CODE' );
	return $self->{callback};
}

sub recursion_callback { &callback; }	## historical


sub bgsend { croak("method bgsend undefined"); }


########################################

sub _hints {				## default hints
	require Net::DNS::ZoneFile;

	my $dug = new Net::DNS::ZoneFile( \*DATA );
	my @rr	= $dug->read;

	my @auth = grep $_->type eq 'NS', @rr;
	my %auth = map { ( lc $_->nsdname => 1 ) } @auth;
	my @glue = grep $auth{lc $_->name}, @rr;
	my %glue;
	push @{$glue{lc $_->name}}, $_->address foreach ( grep $_->type() eq 'A',    @glue );
	push @{$glue{lc $_->name}}, $_->address foreach ( grep $_->type() eq 'AAAA', @glue );
	my @ip = map @$_, values %glue;
}


=head1 ACKNOWLEDGEMENT

This package is an improved and compatible reimplementation of the
Net::DNS::Resolver::Recurse.pm created by Rob Brown in 2002.

The contribution of Rob Brown is gratefully acknowledged.


=head1 COPYRIGHT

Copyright (c)2014 Dick Franks 

Portions Copyright (c)2002 Rob Brown 

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<Net::DNS::Resolver>

=cut


1;


__DATA__	## DEFAULT HINTS

; <<>> DiG 9.9.4-P2-RedHat-9.9.4-15.P2.fc20 <<>> @a.root-servers.net . -t NS
; (2 servers found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4589
;; flags: qr aa rd; QUERY: 1, ANSWER: 13, AUTHORITY: 0, ADDITIONAL: 25
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;.				IN	NS

;; ANSWER SECTION:
.			518400	IN	NS	c.root-servers.net.
.			518400	IN	NS	k.root-servers.net.
.			518400	IN	NS	l.root-servers.net.
.			518400	IN	NS	j.root-servers.net.
.			518400	IN	NS	b.root-servers.net.
.			518400	IN	NS	g.root-servers.net.
.			518400	IN	NS	h.root-servers.net.
.			518400	IN	NS	d.root-servers.net.
.			518400	IN	NS	a.root-servers.net.
.			518400	IN	NS	f.root-servers.net.
.			518400	IN	NS	i.root-servers.net.
.			518400	IN	NS	m.root-servers.net.
.			518400	IN	NS	e.root-servers.net.

;; ADDITIONAL SECTION:
c.root-servers.net.	3600000	IN	A	192.33.4.12
c.root-servers.net.	3600000	IN	AAAA	2001:500:2::c
k.root-servers.net.	3600000	IN	A	193.0.14.129
k.root-servers.net.	3600000	IN	AAAA	2001:7fd::1
l.root-servers.net.	3600000	IN	A	199.7.83.42
l.root-servers.net.	3600000	IN	AAAA	2001:500:3::42
j.root-servers.net.	3600000	IN	A	192.58.128.30
j.root-servers.net.	3600000	IN	AAAA	2001:503:c27::2:30
b.root-servers.net.	3600000	IN	A	192.228.79.201
b.root-servers.net.	3600000	IN	AAAA	2001:500:84::b
g.root-servers.net.	3600000	IN	A	192.112.36.4
h.root-servers.net.	3600000	IN	A	128.63.2.53
h.root-servers.net.	3600000	IN	AAAA	2001:500:1::803f:235
d.root-servers.net.	3600000	IN	A	199.7.91.13
d.root-servers.net.	3600000	IN	AAAA	2001:500:2d::d
a.root-servers.net.	3600000	IN	A	198.41.0.4
a.root-servers.net.	3600000	IN	AAAA	2001:503:ba3e::2:30
f.root-servers.net.	3600000	IN	A	192.5.5.241
f.root-servers.net.	3600000	IN	AAAA	2001:500:2f::f
i.root-servers.net.	3600000	IN	A	192.36.148.17
i.root-servers.net.	3600000	IN	AAAA	2001:7fe::53
m.root-servers.net.	3600000	IN	A	202.12.27.33
m.root-servers.net.	3600000	IN	AAAA	2001:dc3::35
e.root-servers.net.	3600000	IN	A	192.203.230.10

;; Query time: 29 msec
;; SERVER: 198.41.0.4#53(198.41.0.4)
;; WHEN: Mon Aug 11 14:39:19 BST 2014
;; MSG SIZE  rcvd: 755

