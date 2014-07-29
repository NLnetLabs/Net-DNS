package Net::DNS::Resolver::MSWin32;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];

=head1 NAME

Net::DNS::Resolver::MSWin32 - MS Windows Resolver Class

=cut


use strict;
use base qw(Net::DNS::Resolver::Base);

use Carp;
use Data::Dumper;

BEGIN {
	use vars qw($Registry);

	use constant WINHLP => eval {	## use Win32::Helper;	# hidden from static analyser
		require Win32::IPHelper;
	} || 0;

	Win32::IPHelper->import if WINHLP;

	use constant WINREG => eval {	## use Win32::TieRegistry;
		require Win32::TieRegistry;
	} || 0;

	Win32::TieRegistry->import(qw(KEY_READ REG_DWORD)) if WINREG;
}


sub _untaint { map defined && /^(.+)$/ ? $1 : (), @_; }


sub init {
	my $defaults = shift->defaults;

	my $debug = 0;

	my $FIXED_INFO = {};

	unless ( my $ret = Win32::IPHelper::GetNetworkParams($FIXED_INFO) ) {
		print Dumper $FIXED_INFO if $debug;
	} else {
		Carp::croak "GetNetworkParams() error %u: %s\n", $ret, Win32::FormatMessage($ret);
	}


	my @nameservers = map { $_->{IpAddress} } @{$FIXED_INFO->{DnsServersList}};
	$defaults->nameservers( _untaint @nameservers );

	my @searchlist = _untaint lc $FIXED_INFO->{DomainName};
	$defaults->domain(@searchlist);

	my $usedevolution = 0;

	if (WINREG) {

		# The Win32::IPHelper does not return searchlist.
		# Make best effort attempt to get searchlist from the registry.

		my @root = qw(HKEY_LOCAL_MACHINE SYSTEM CurrentControlSet Services);

		my $leaf = join '\\', @root, qw(Tcpip Parameters);
		my $reg_tcpip = $Registry->Open( $leaf, {Access => KEY_READ} );

		unless ( defined $reg_tcpip ) {			# Didn't work, Win95/98/Me?
			$leaf = join '\\', @root, qw(VxD MSTCP);
			$reg_tcpip = $Registry->Open( $leaf, {Access => KEY_READ} );
		}

		if ( defined $reg_tcpip ) {
			my $searchlist = lc $reg_tcpip->GetValue('SearchList') || '';
			push @searchlist, split m/[\s,]+/, $searchlist;

			my ( $value, $type ) = $reg_tcpip->GetValue('UseDomainNameDevolution');
			$usedevolution = defined $value && $type == REG_DWORD ? hex $value : 0;
		}
	}


	# fix devolution if configured, and simultaneously
	# make sure no dups (but keep the order)
	my @a;
	my %h;
	foreach my $entry (@searchlist) {
		push( @a, $entry ) unless $h{$entry}++;

		if ($usedevolution) {

			# as long there are more than two pieces, cut
			while ( $entry =~ m#\..+\.# ) {
				$entry =~ s#^[^\.]+\.(.+)$#$1#;
				push( @a, $entry ) unless $h{$entry}++;
			}
		}
	}
	$defaults->searchlist( _untaint @a );

	$defaults->read_env;
}


1;
__END__


=head1 SYNOPSIS

    use Net::DNS::Resolver;

=head1 DESCRIPTION

This class implements the OS specific portions of C<Net::DNS::Resolver>.

No user serviceable parts inside, see L<Net::DNS::Resolver|Net::DNS::Resolver>
for all your resolving needs.

=head1 COPYRIGHT

Copyright (c)1997-2002 Michael Fuhr.

Portions Copyright (c)2002-2004 Chris Reinhardt.

Portions Copyright (c)2009 Olaf Kolkman, NLnet Labs

All rights reserved.  This program is free software; you may redistribute
it and/or modify it under the same terms as Perl itself.

=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::Resolver>

=cut
