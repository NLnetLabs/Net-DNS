package Net::DNS::Resolver::Win32;
#
# $Id: Win32.pm,v 1.3 2003/08/26 23:58:10 ctriv Exp $
#

use strict;
use vars qw(@ISA $VERSION);

use Net::DNS::Resolver::Base ();

@ISA     = qw(Net::DNS::Resolver::Base);
$VERSION = (qw$Revision: 1.3 $)[1];

use Win32::Registry;

sub init {
	my ($class) = @_;
	
	my $defaults = $class->defaults;
	
	my ($resobj, %keys);

	my $root = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters';
	unless ($main::HKEY_LOCAL_MACHINE->Open($root, $resobj)) {
		# Didn't work, maybe we are on 95/98/Me?
		$root = 'SYSTEM\CurrentControlSet\Services\VxD\MSTCP';
		$main::HKEY_LOCAL_MACHINE->Open($root, $resobj)
			or Carp::croak "can't read registry: $!";
	}

	$resobj->GetValues(\%keys)
		or Carp::croak "can't read registry values: $!";

	# Best effort to find a useful domain name for the current host
	# if domain ends up blank, we're probably (?) not connected anywhere
	# a DNS server is interesting either...
	my $domain      = $keys{'Domain'}->[2] || $keys{'DhcpDomain'}->[2];
	
	# If nothing else, the searchlist should probably contain our own domain
	# also see below for domain name devolution if so configured
	# (also remove any duplicates later)
	my $searchlist = "$domain ";
	$searchlist  .= $keys{'SearchList'}->[2];
	
	# This is (probably) adequate on NT4
	my $nameservers = $keys{'NameServer'}->[2] || $keys{'DhcpNameServer'}->[2];
	#
	# but on W2K/XP the registry layout is more advanced due to dynamically
	# appearing connections. So we attempt to handle them, too...
	# opt to silently fail if something isn't ok (maybe we're on NT4)
	# drop any duplicates later
	my $dnsadapters;
	$resobj->Open("DNSRegisteredAdapters", $dnsadapters);
	if ($dnsadapters) {
		my @adapters;
		$dnsadapters->GetKeys(\@adapters);
		foreach my $adapter (@adapters) {
			my $regadapter;
			$dnsadapters->Open($adapter, $regadapter);
			if ($regadapter) {
				my($type,$ns);
				$regadapter->QueryValueEx("DNSServerAddresses", $type, $ns);
				while (length($ns) >= 4) {
					my $addr = join('.', unpack("C4", substr($ns,0,4,"")));
					$nameservers .= " $addr";
				}
			}
		}
	}

	my $interfaces;
	$resobj->Open("Interfaces", $interfaces);
	if ($interfaces) {
		my @ifacelist;
		$interfaces->GetKeys(\@ifacelist);
		foreach my $iface (@ifacelist) {
			my $regiface;
			$interfaces->Open($iface, $regiface);
			if ($regiface) {
				my $ns;
				my $type;
				$regiface->QueryValueEx("NameServer", $type, $ns);
				$nameservers .= " $ns" if $ns;
				$regiface->QueryValueEx("DhcpNameServer", $type, $ns);
				$nameservers .= " $ns" if $ns;
			}
		}
	}

	if ($domain) {
		$defaults->{'domain'} = $domain;
	}

	my $usedevolution = $keys{'UseDomainNameDevolution'}->[2];
	if ($searchlist) {
		# fix devolution if configured, and simultaneously make sure no dups (but keep the order)
		my $i = 0;
		my %h;
		foreach my $entry (split(m/[\s,]+/, $searchlist)) {
			$h{$entry} = $i++;
			if ($usedevolution) {
				# as long there's more than two pieces, cut
				while ($entry =~ m#\..+\.#) {
					$entry =~ s#^[^\.]+\.(.+)$#$1#;
					$h{$entry} = $i++;
					}
				}
			}
		my @a;
		$a[$h{$_}] = $_ foreach (keys %h);
		$defaults->{'searchlist'} = \@a;
	}

	if ($nameservers) {
		# just in case dups were introduced...
		my @a;
		my %h;
		foreach my $ns (split(m/[\s,]+/, $nameservers)) {
			push @a, $ns unless $h{$ns};
			$h{$ns} = 1;
		}
		$defaults->{'nameservers'} = \@a;
	}

	$class->read_env;

	if (!$defaults->{'domain'} && @{$defaults->{'searchlist'}}) {
		$defaults->{'domain'} = $defaults->{'searchlist'}[0];
	} elsif (!@{$defaults->{'searchlist'}} && $defaults->{'domain'}) {
		$defaults->{'searchlist'} = [ $defaults->{'domain'} ];
	}

	$defaults->{'usevc'} = 1;
	$defaults->{'tcp_timeout'} = undef;
}

1;
__END__
