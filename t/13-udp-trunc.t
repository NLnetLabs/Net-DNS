# $Id$ -*-perl-*-
# Bulk of this code is contributed by Aaron Crane in 2008
# via rt.cpan.org ticket 33547
# Portions (c) 2009 Olaf Kolkman

use Test::More;
use strict;
use Data::Dumper;

my $ZONE = 'example.com';

use_ok('Net::DNS::Nameserver');

use vars qw(
	    $Address
	    $TestPort
            $numberoftests
	    );

BEGIN{
    $TestPort  = 5334;
    $Address = "127.0.0.1";

    $numberoftests=100;
    
    if(
	eval {require IO::Socket;}
	){
	#Try binding to the test addresses .. 
	diag ("Testing availability of $Address");
	my $s = IO::Socket::INET->new(Proto => 'udp',
				      LocalAddr => $Address,
				      LocalPort => $TestPort
	    );
	
	
	
	unless ($s){
	    diag ("This test needs ".join (" ",$Address). " to be configured on your system, and port $TestPort needs to be available for binding");
	    
	    plan skip_all =>  "$Address has not been configured";
	    exit;
	    
	}
	close ($s);

	plan tests => $numberoftests;
    }else{
	
	plan skip_all => 'Some modules required for this test are not available (dont\'t worry about this)';          
	exit;
    }
    
}


{
    my @full_response;
    my $ns = Net::DNS::Nameserver->new(
        LocalPort    => $TestPort,
	LocalAddr    => $Address,
        ReplyHandler => sub { NOERROR => @full_response },
    );
    for (trad_query(), edns_query(1024), edns_query(2048)) {
        my ($query, $size) = @$_;
        for my $n ( 
	    [1, 1, 1],
	    [5, 1, 1],
	    [10, 1, 1],
	    [1, 1, 30],
	    [40, 40, 40],
	    [50, 1, 1],
	    [1, 50, 1],
	    [20, 20, 1],
	    [20, 1, 50],
	    [60, 60, 60],
	    [60, 100, 60],
	    ) {
            @full_response = make_response($n);
	    

	    my $notcomp=Net::DNS::Packet->new();
	    $notcomp->push("question", $query->question);
	    my ($ans, $auth, $add)=@full_response;
	    $notcomp->push("answer",	 @$ans)  if $ans;
	    $notcomp->push("authority",  @$auth) if $auth;
	    $notcomp->push("additional", @$add)  if $add;
	    #$notcomp->print;
            my $socket = Mock::UDP->new($query->data);
            $ns->udp_connection($socket);
            my $reply_data = $socket->output;
	    my $reply = Net::DNS::Packet->new(\$reply_data);
	    #$reply->print;
	    
	    cmp_ok(length $reply_data, '<=', $size,
		   "UDP-$size reply for\t($n->[0] , $n->[1], $n->[2])\t records short enough ($size: ".length($notcomp->data) ."->". length ( $reply_data ) . ")") || $reply->print;
            ok($reply, "UDP-$size reply for\t($n->[0] , $n->[1], $n->[2])\t received answer");
            my $got      = reply_records($reply);
            my $expected = response_records($query, @full_response);
            ok(is_prefix($reply->header->tc, $got, $expected),
               "UDP-$size reply for\t($n->[0] , $n->[1], $n->[2])\t records complete or sanely truncated");
        }
    }
}

sub trad_query {
    return [Net::DNS::Packet->new($ZONE), 512];
}

sub edns_query {
    my $size = shift;
    my $edns_rr = Net::DNS::RR->new(type => 'OPT', class => $size, name => '');
    my $query = Net::DNS::Packet->new($ZONE);
    $query->push(additional => $edns_rr);
    return [$query, $size];
}

sub reply_records {
    my ($reply) = @_;
    my @records;
    for my $section (qw<question answer authority additional>) {
        push @records, map { [$section => $_] } $reply->$section;
    }
    return \@records;
}

sub response_records {
    my ($query, @response) = @_;
    unshift @response, [$query->question];
    my @records;
    for my $section (qw<question answer authority additional>) {
        push @records, map { [$section => $_] } @{ shift @response };
    }
    return \@records;
}

sub is_prefix {
    my ($truncated, $got_list, $expected_list) = @_;
    die 'TEST BUG: no records expected' if !@$expected_list;
    if (@$got_list > @$expected_list) {
        diag("Most peculiar: got too many records");
        return 0;
    }
    my @seen;

    my $rr_got;
    my $rr_exp;

    # Start investigating the additonal section
    # if we find an RR with a certain (name,class,type) in the additonal section (in got) then
    # we expect all RRs from from that (name,class,type) from the expected array to be in the packet.

    # if a certain RR (name,class,type) from the expected array is not found in the packet than all
    # RRs from that set expect to be stripped.


    foreach my $tst ( @$expected_list ){
	next unless $tst->[0] eq "additional";
	$rr_exp->{$tst->[1]->name. "--".
		      $tst->[1]->class. "--".
		      $tst->[1]->type}{$tst->[1]->rdatastr} = 1;
	
    }

    foreach my $tst ( @$got_list ){
	next unless $tst->[0] eq "additional";
	$rr_got->{$tst->[1]->name. "--".
		      $tst->[1]->class. "--".
		      $tst->[1]->type}{$tst->[1]->rdatastr} = 1;
    }
	

    foreach my $a (keys %$rr_exp){
	if (defined $rr_got->{$a}){
	    foreach my $b (keys %{$rr_got->{$a}}){
		if  (defined($rr_exp->{$a}->{$b})){
		    delete $rr_got->{$a}->{$b};
		    delete $rr_exp->{$a}->{$b};
		}
		delete $rr_got->{$a} unless (keys %{$rr_got->{$a}});
		delete $rr_exp->{$a} unless (keys %{$rr_exp->{$a}});
	    }

	}else{
	    delete $rr_exp->{ $a }
	    
	}
    }

    if (my @a=keys %$rr_exp){
	foreach my $a ( @a) {
	    diag ("One RR of name-class-type $a got stripped from the packet while leaving others in the additional section");
	}
	return 0;
    }

    if (my @b=keys %$rr_got){
	foreach my $b ( @b) {
	    diag ("One RR of name-class-type $b did not get stripped from the additional section");
	}
	return 0;
    }



    
    for (;;) {
        #return !$truncated == !@$expected_list if !@$got_list;
	last if ! @$got_list;
        my $got      = shift @$got_list;
	push @seen, $got;
        my $expected = shift @$expected_list;
	my ($got_s, $expected_s) = map { $_->[1]->string } $got, $expected;


       	if ($got->[0] eq "additional" && $expected->[0] eq "additional"){
	    # this is the situation where we are looking at the truncated additional section.
	    # Since there are still records left the the TC bit should not be set.
	    if ($truncated){
		diag ("There are still records in the additonal section but the truncation bit seems set");
		return 0;
	    }
	    next;
	}elsif ($got->[0] ne $expected->[0] || $got_s ne $expected_s) {
            diag("Got[$got->[0] $got_s] Expected[$expected->[0] $expected_s]");
            return 0;
        }
    }

    return(1);
    
}

sub make_response {
    my ($n,$m,$p) = @{shift()};
    # create sets of nameservers ns0... ns2
    my @ans  = map { Net::DNS::RR->new("$ZONE 9 IN A 10.0.0.$_") } 1 .. $n;
    my @auth = map { Net::DNS::RR->new("$ZONE 9 IN NS ns". $_%3 .".$ZONE")    } 1 .. $m;
    my @add  = map { Net::DNS::RR->new("ns". $_%3 .".$ZONE 9 IN A 10.0.1.".$_%256) } 1 .. $p;
    return \@ans, \@auth, \@add;
}



{
package Mock::UDP;

sub new {
    my ($class, $data) = @_;
    return bless {
	input  => $data,
	output => '',
    }, $class;
}

sub peerhost { '127.0.0.1' }
sub peerport { 65534 }
sub output   { $_[0]{output} }
sub sockhost {$main::Address}
sub sockport {$main::TestPort}
sub recv {
    my ($self, $buf, $len) = @_;
    return if $self->{input} eq '';
    my $data = substr $self->{input}, 0, $len, '';
    $_[1] = $data;
}

sub send {
    my ($self, $data) = @_;
    $self->{output} .= $data;
    1;
}
}
