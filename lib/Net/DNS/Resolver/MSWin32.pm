package Net::DNS::Resolver::MSWin32;
use base Net::DNS::Resolver::Base;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1]; # Unchanged since 1045

=head1 NAME

Net::DNS::Resolver::MSWin32 - MS Windows Resolver Class

=cut


use strict;
use Win32::IPHelper;
use Win32::TieRegistry qw(KEY_READ REG_DWORD);
use Data::Dumper;

sub init {

	my $debug = 0;
	my ($class) = @_;

	my $defaults = $class->defaults;


	my $FIXED_INFO = {};

	my $ret = Win32::IPHelper::GetNetworkParams($FIXED_INFO);

	if ( $ret == 0 ) {
		print Dumper $FIXED_INFO if $debug;
	} else {

		Carp::croak "GetNetworkParams() error %u: %s\n", $ret, Win32::FormatMessage($ret);
	}


	my @nameservers = map { $_->{IpAddress} } @{$FIXED_INFO->{DnsServersList}};

	my %h;							# remove blanks and dupes
	$defaults->{nameservers} = [grep { $_ && !$h{$_}++ } @nameservers] if scalar @nameservers;

	my $domain = $FIXED_INFO->{DomainName} || '';
	my $searchlist = $domain;
	$defaults->{domain} = $domain if $domain;


	#
	# The Win32::IPHelper  does not return searchlist. Lets do a best effort attempt to get
	# a searchlist from the registry.

	my $usedevolution = 0;

	my $root = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters';
	my $reg_tcpip = $Registry->Open( $root, {Access => KEY_READ} );
	if ( !defined $reg_tcpip ) {

		# Didn't work, maybe we are on 95/98/Me?
		$root = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VxD\MSTCP';
		$reg_tcpip = $Registry->Open( $root, {Access => KEY_READ} );
	}

	if ( defined $reg_tcpip ) {
		$searchlist .= ',' if $searchlist;		# $domain already in there
		$searchlist .= ( $reg_tcpip->GetValue('SearchList') || "" );
		my ( $value, $type ) = $reg_tcpip->GetValue('UseDomainNameDevolution');
		$usedevolution = defined $value && $type == REG_DWORD ? hex $value : 0;
	}

	if ($searchlist) {

		# fix devolution if configured, and simultaneously make sure no dups (but keep the order)
		my @a;
		my %h;
		foreach my $entry ( split( m/[\s,]+/, lc $searchlist ) ) {
			push( @a, $entry ) unless $h{$entry}++;

			if ($usedevolution) {

				# as long there are more than two pieces, cut
				while ( $entry =~ m#\..+\.# ) {
					$entry =~ s#^[^\.]+\.(.+)$#$1#;
					push( @a, $entry ) unless $h{$entry}++;
				}
			}
		}
		$defaults->{searchlist} = [@a];
	}


	$class->read_env;


	if ( !$defaults->{domain} && @{$defaults->{searchlist}} ) {
		$defaults->{domain} = $defaults->{searchlist}[0];
	} elsif ( !@{$defaults->{searchlist}} && $defaults->{domain} ) {
		$defaults->{searchlist} = [$defaults->{domain}];
	}

	print Dumper $defaults if $debug;

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
