package Net::DNS::Update;

#
# $Id$
#
use vars qw($VERSION @ISA);
$VERSION = (qw$LastChangedRevision$)[1];


=head1 NAME

Net::DNS::Update - DNS dynamic update packet

=head1 SYNOPSIS

    use Net::DNS;

    $update = new Net::DNS::Update( 'example.com', 'IN' );

    $update->push( prereq => nxrrset('foo.example.com. A') );
    $update->push( update => rr_add('foo.example.com. 86400 A 192.168.1.2') );

=head1 DESCRIPTION

Net::DNS::Update is a subclass of Net::DNS::Packet, to be used for
making DNS dynamic updates.

Programmers should refer to RFC2136 for dynamic update semantics.

=cut


use strict;
use base 'Net::DNS::Packet';


=head1 METHODS

=head2 new

    $update = new Net::DNS::Update;
    $update = new Net::DNS::Update( 'example.com' );
    $update = new Net::DNS::Update( 'example.com', 'HS' );

Returns a Net::DNS::Update object suitable for performing a DNS
dynamic update.	 Specifically, it creates a packet with the header
opcode set to UPDATE and the zone record type to SOA (per RFC 2136,
Section 2.3).

Programs must use the push() method to add RRs to the prerequisite,
update, and additional sections before performing the update.

Arguments are the zone name and the class.  If the zone is omitted,
the default domain will be taken from the resolver configuration.
If the class is omitted, it defaults to IN.

=cut

sub new {
	my $package = shift;
	my ( $zone, $class ) = @_;

	unless ($zone) {
		require Net::DNS::Resolver;
		my $resolver = new Net::DNS::Resolver();	# create resolver object

		($zone) = $resolver->searchlist;
		return unless $zone;
	}

	return $package->SUPER::decode(@_) if ref($zone);

	my $self = $package->SUPER::new( $zone, 'SOA', $class ) || return;

	$self->header->opcode('UPDATE');
	$self->header->rd(0);

	return $self;
}


1;

__END__


=head1 EXAMPLES

The first example below shows a complete program;
subsequent examples show only the creation of the update packet .

=head2 Add a new host

    #!/usr/bin/perl

    use Net::DNS;

    # Create the update packet.
    my $update = new Net::DNS::Update('example.com');

    # Prerequisite is that no A records exist for the name.
    $update->push( pre => nxrrset('foo.example.com. A') );

    # Add two A records for the name.
    $update->push( update => rr_add('foo.example.com. 86400 A 192.168.1.2') );
    $update->push( update => rr_add('foo.example.com. 86400 A 172.16.3.4') );

    # Send the update to the zone's primary master.
    my $resolver = new Net::DNS::Resolver;
    $resolver->nameservers('primary-master.example.com');

    my $reply = $resolver->send($update);

    # Did it work?
    if ($reply) {
	    if ( $reply->header->rcode eq 'NOERROR' ) {
		    print "Update succeeded\n";
	    } else {
		    print 'Update failed: ', $reply->header->rcode, "\n";
	    }
    } else {
	    print 'Update failed: ', $resolver->errorstring, "\n";
    }


=head2 Add an MX record for a name that already exists

    my $update = new Net::DNS::Update('example.com');
    $update->push( prereq => yxdomain('example.com') );
    $update->push( update => rr_add('example.com MX 10 mailhost.example.com') );

=head2 Add a TXT record for a name that doesn't exist

    my $update = new Net::DNS::Update('example.com');
    $update->push( prereq => nxdomain('info.example.com') );
    $update->push( update => rr_add('info.example.com TXT "yabba dabba doo"') );

=head2 Delete all A records for a name

    my $update = new Net::DNS::Update('example.com');
    $update->push( prereq => yxrrset('foo.example.com A') );
    $update->push( update => rr_del('foo.example.com A') );

=head2 Delete all RRs for a name

    my $update = new Net::DNS::Update('example.com');
    $update->push( prereq => yxdomain('byebye.example.com') );
    $update->push( update => rr_del('byebye.example.com') );

=head2 Perform a DNS update signed using a BIND private key file

    my $update = new Net::DNS::Update('example.com');
    $update->push( update => rr_add('foo.example.com A 10.1.2.3') );
    $update->sign_tsig( "$dir/Khmac-sha512.example.com.+165+01018.private" );
    my $reply = $resolver->send( $update );
    $reply->verify( $update ) || die $reply->verifyerr;

=head2 Signing the DNS update using a BIND public key file

    $update->sign_tsig( "$dir/Khmac-sha512.example.com.+165+01018.key" );

=head2 Signing the DNS update using a customised TSIG record

    $update->sign_tsig( "$dir/Khmac-sha512.example.com.+165+01018.private",
                        fudge => 60
                        );

=head2 Another way to sign a DNS update

    my $key_name = 'tsig-key';
    my $key	 = 'awwLOtRfpGE+rRKF2+DEiw==';

    my $tsig = new Net::DNS::RR("$key_name TSIG $key");
    $tsig->fudge(60);

    my $update = new Net::DNS::Update('example.com');
    $update->push( update     => rr_add('foo.example.com A 10.1.2.3') );
    $update->push( additional => $tsig );


=head1 COPYRIGHT

Copyright (c) 1997-2002 Michael Fuhr. 

Portions Copyright (c) 2002-2004 Chris Reinhardt.

All rights reserved.  This program is free software; you may redistribute
it and/or modify it under the same terms as Perl itself.

=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::Packet>, L<Net::DNS::Header>,
L<Net::DNS::RR>, L<Net::DNS::Resolver>, RFC 2136, RFC 2845

=cut

