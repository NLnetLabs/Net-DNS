# $Id: 05-rr.t,v 1.2 1997/07/06 16:41:37 mfuhr Exp $

BEGIN { $| = 1; print "1..202\n"; }
END {print "not ok 1\n" unless $loaded;}

use Net::DNS;

$loaded = 1;
print "ok 1\n";

#------------------------------------------------------------------------------
# Canned data.
#------------------------------------------------------------------------------

$name			= "foo.bar.com";
$class			= "IN";
$ttl			= 43200;

$a_address		= "10.0.0.1";

$aaaa_address		= "102:304:506:708:90a:b0c:d0e:ff10";

$afsdb_subtype		= 1;
$afsdb_hostname		= "afsdb-hostname.bar.com";

$cname_cname		= "cname-cname.bar.com";

# EID

$hinfo_cpu		= "test-cpu";
$hinfo_os		= "test-os";

$isdn_address		= "987654321";
$isdn_sa		= "001";

$loc_version		= 0;
$loc_size		= 3000;
$loc_horiz_pre		= 500000;
$loc_vert_pre		= 500;
$loc_latitude		= 2001683648;
$loc_longitude		= 1856783648;
$loc_altitude		= 9997600;

$mb_madname		= "mb-madname.bar.com";

$mg_mgmname		= "mg-mgmname.bar.com";

$minfo_rmailbx		= "minfo-rmailbx.bar.com";
$minfo_emailbx		= "minfo-emailbx.bar.com";

$mr_newname		= "mr-newname.bar.com";

$mx_preference		= 10;
$mx_exchange		= "mx-exchange.bar.com";

$naptr_order		= 100;
$naptr_preference	= 10;
$naptr_flags		= "naptr-flags";
$naptr_service		= "naptr-service";
$naptr_regexp		= "naptr-regexp";
$naptr_replacement	= "naptr-replacement.bar.com";

# NIMLOC

$ns_nsdname		= "ns-nsdname.bar.com";

$nsap_afi		= "47";
$nsap_idi		= "0005";
$nsap_dfi		= "80";
$nsap_aa		= "005a00";
$nsap_rd		= "1000";
$nsap_area		= "0020";
$nsap_id		= "00800a123456";
$nsap_sel		= "00";

# NULL

$ptr_ptrdname		= "ptr-ptrdname.bar.com";

$px_preference		= 10;
$px_map822		= "px-map822.bar.com";
$px_mapx400		= "px-mapx400.bar.com";

$rp_mbox		= "rp-mbox.bar.com";
$rp_txtdname		= "rp-txtdname.bar.com";

$rt_preference		= 10;
$rt_intermediate	= "rt-intermediate.bar.com";

$soa_mname		= "soa-mname.bar.com";
$soa_rname		= "soa-rname.bar.com";
$soa_serial		= 12345;
$soa_refresh		= 7200;
$soa_retry		= 3600;
$soa_expire		= 2592000;
$soa_minimum		= 86400;

$srv_priority		= 1;
$srv_weight		= 2;
$srv_port		= 3;
$srv_target		= "srv-target.bar.com";

$txt_txtdata		= "txt-txtdata";

$x25_psdn		= 123456789;

#------------------------------------------------------------------------------
# Create the packet.
#------------------------------------------------------------------------------

$packet = new Net::DNS::Packet($name);
print "not " unless defined $packet;
print "ok 2\n";

# answer[0]
$packet->push("answer", new Net::DNS::RR(
	Name	=> $name,
	Type	=> "A",
	TTL	=> $ttl,
	Address	=> $a_address));

# answer[1]
$packet->push("answer", new Net::DNS::RR(
	Name	=> $name,
	Type	=> "AAAA",
	TTL	=> $ttl,
	Address	=> $aaaa_address));

# answer[2]
$packet->push("answer", new Net::DNS::RR(
	Name	 => $name,
	Type	 => "AFSDB",
	TTL	 => $ttl,
	Subtype	 => $afsdb_subtype,
	Hostname => $afsdb_hostname));

# answer[3]
$packet->push("answer", new Net::DNS::RR(
	Name	=> $name,
	Type	=> "CNAME",
	TTL	=> $ttl,
	Cname	=> $cname_cname));

# answer[4]
$packet->push("answer", new Net::DNS::RR(
	Name	=> $name,
	Type	=> "HINFO",
	TTL	=> $ttl,
	CPU	=> $hinfo_cpu,
	OS	=> $hinfo_os));

# answer[5]
$packet->push("answer", new Net::DNS::RR(
	Name	=> $name,
	Type	=> "ISDN",
	TTL	=> $ttl,
	Address	=> $isdn_address,
	SA	=> $isdn_sa));

# answer[6]
$packet->push("answer", new Net::DNS::RR(
	Name	=> $name,
	Type	=> "MB",
	TTL	=> $ttl,
	Madname	=> $mb_madname));

# answer[7]
$packet->push("answer", new Net::DNS::RR(
	Name	=> $name,
	Type	=> "MG",
	TTL	=> $ttl,
	Mgmname	=> $mg_mgmname));

# answer[8]
$packet->push("answer", new Net::DNS::RR(
	Name	=> $name,
	Type	=> "MINFO",
	TTL	=> $ttl,
	Rmailbx	=> $minfo_rmailbx,
	Emailbx	=> $minfo_emailbx));

# answer[9]
$packet->push("answer", new Net::DNS::RR(
	Name	=> $name,
	Type	=> "MR",
	TTL	=> $ttl,
	Newname	=> $mr_newname));

# answer[10]
$packet->push("answer", new Net::DNS::RR(
	Name	   => $name,
	Type	   => "MX",
	TTL	   => $ttl,
	Preference => $mx_preference,
	Exchange   => $mx_exchange));

# answer[11]
$packet->push("answer", new Net::DNS::RR(
	Name	    => $name,
	Type	    => "NAPTR",
	TTL	    => $ttl,
	Order	    => $naptr_order,
	Preference  => $naptr_preference,
	Flags	    => $naptr_flags,
	Service	    => $naptr_service,
	Regexp	    => $naptr_regexp,
	Replacement => $naptr_replacement));

# answer[12]
$packet->push("answer", new Net::DNS::RR(
	Name	=> $name,
	Type	=> "NS",
	TTL	=> $ttl,
	Nsdname	=> $ns_nsdname));

# answer[13]
$packet->push("answer", new Net::DNS::RR(
	Name	=> $name,
	Type	=> "NSAP",
	TTL	=> $ttl,
	AFI	=> $nsap_afi,
	IDI	=> $nsap_idi,
	DFI	=> $nsap_dfi,
	AA	=> $nsap_aa,
	RD	=> $nsap_rd,
	Area	=> $nsap_area,
	ID	=> $nsap_id,
	Sel	=> $nsap_sel));

# answer[14]
$packet->push("answer", new Net::DNS::RR(
	Name	 => $name,
	Type	 => "PTR",
	TTL	 => $ttl,
	Ptrdname => $ptr_ptrdname));

# answer[15]
$packet->push("answer", new Net::DNS::RR(
	Name	   => $name,
	Type	   => "PX",
	TTL	   => $ttl,
	Preference => $px_preference,
	Map822	   => $px_map822,
	MapX400	   => $px_mapx400));

# answer[16]
$packet->push("answer", new Net::DNS::RR(
	Name	 => $name,
	Type	 => "RP",
	TTL	 => $ttl,
	Mbox	 => $rp_mbox,
	Txtdname => $rp_txtdname));

# answer[17]
$packet->push("answer", new Net::DNS::RR(
	Name	     => $name,
	Type	     => "RT",
	TTL	     => $ttl,
	Preference   => $rt_preference,
	Intermediate => $rt_intermediate));

# answer[18]
$packet->push("answer", new Net::DNS::RR(
	Name	=> $name,
	Type	=> "SOA",
	TTL	=> $ttl,
	Mname	=> $soa_mname,
	Rname	=> $soa_rname,
	Serial	=> $soa_serial,
	Refresh	=> $soa_refresh,
	Retry	=> $soa_retry,
	Expire	=> $soa_expire,
	Minimum	=> $soa_minimum));

# answer[19]
$packet->push("answer", new Net::DNS::RR(
	Name	 => $name,
	Type	 => "SRV",
	TTL	 => $ttl,
	Priority => $srv_priority,
	Weight	 => $srv_weight,
	Port	 => $srv_port,
	Target	 => $srv_target));

# answer[20]
$packet->push("answer", new Net::DNS::RR(
	Name	=> $name,
	Type	=> "TXT",
	TTL	=> $ttl,
	Txtdata	=> $txt_txtdata));

# answer[21]
$packet->push("answer", new Net::DNS::RR(
	Name	=> $name,
	Type	=> "X25",
	TTL	=> $ttl,
	PSDN	=> $x25_psdn));

# answer[22]
$packet->push("answer", new Net::DNS::RR(
	Name      => $name,
	Type      => "LOC",
	TTL       => $ttl,
	Version   => $loc_version,
	Size      => $loc_size,
	Horiz_Pre => $loc_horiz_pre,
	Vert_Pre  => $loc_vert_pre,
	Latitude  => $loc_latitude,
	Longitude => $loc_longitude,
	Altitude  => $loc_altitude));

#------------------------------------------------------------------------------
# Re-create the packet from data.
#------------------------------------------------------------------------------

$data = $packet->data;
print "not " unless defined $data;
print "ok 3\n";

undef $packet;
$packet = new Net::DNS::Packet(\$data);
print "not " unless defined $packet;
print "ok 4\n";

@answer = $packet->answer;
print "not " unless defined @answer;
print "ok 5\n";

#------------------------------------------------------------------------------
# A record
#------------------------------------------------------------------------------

$rr = $answer[0];
print "not " unless defined $rr;
print "ok 6\n";

print "not " unless $rr->name eq $name;
print "ok 7\n";

print "not " unless $rr->class eq $class;
print "ok 8\n";

print "not " unless $rr->type eq "A";
print "ok 9\n";

print "not " unless $rr->ttl == $ttl;
print "ok 10\n";

print "not " unless $rr->address eq $a_address;
print "ok 11\n";

$rr2 = new Net::DNS::RR($rr->string);
print "not " unless $rr2->string eq $rr->string;
print "ok 12\n";

#------------------------------------------------------------------------------
# AAAA record
#------------------------------------------------------------------------------

$rr = $answer[1];
print "not " unless defined $rr;
print "ok 13\n";

print "not " unless $rr->name eq $name;
print "ok 14\n";

print "not " unless $rr->class eq $class;
print "ok 15\n";

print "not " unless $rr->type eq "AAAA";
print "ok 16\n";

print "not " unless $rr->ttl == $ttl;
print "ok 17\n";

print "not " unless $rr->address eq $aaaa_address;
print "ok 18\n";

$rr2 = new Net::DNS::RR($rr->string);
print "not " unless $rr2->string eq $rr->string;
print "ok 19\n";

#------------------------------------------------------------------------------
# AFSDB record
#------------------------------------------------------------------------------

$rr = $answer[2];
print "not " unless defined $rr;
print "ok 20\n";

print "not " unless $rr->name eq $name;
print "ok 21\n";

print "not " unless $rr->class eq $class;
print "ok 22\n";

print "not " unless $rr->type eq "AFSDB";
print "ok 23\n";

print "not " unless $rr->ttl == $ttl;
print "ok 24\n";

print "not " unless $rr->subtype == $afsdb_subtype;
print "ok 25\n";

print "not " unless $rr->hostname eq $afsdb_hostname;
print "ok 26\n";

$rr2 = new Net::DNS::RR($rr->string);
print "not " unless $rr2->string eq $rr->string;
print "ok 27\n";

#------------------------------------------------------------------------------
# CNAME record
#------------------------------------------------------------------------------

$rr = $answer[3];
print "not " unless defined $rr;
print "ok 28\n";

print "not " unless $rr->name eq $name;
print "ok 29\n";

print "not " unless $rr->class eq $class;
print "ok 30\n";

print "not " unless $rr->type eq "CNAME";
print "ok 31\n";

print "not " unless $rr->ttl == $ttl;
print "ok 32\n";

print "not " unless $rr->cname eq $cname_cname;
print "ok 33\n";

$rr2 = new Net::DNS::RR($rr->string);
print "not " unless $rr2->string eq $rr->string;
print "ok 34\n";

#------------------------------------------------------------------------------
# HINFO record
#------------------------------------------------------------------------------

$rr = $answer[4];
print "not " unless defined $rr;
print "ok 35\n";

print "not " unless $rr->name eq $name;
print "ok 36\n";

print "not " unless $rr->class eq $class;
print "ok 37\n";

print "not " unless $rr->type eq "HINFO";
print "ok 38\n";

print "not " unless $rr->ttl == $ttl;
print "ok 39\n";

print "not " unless $rr->cpu eq $hinfo_cpu;
print "ok 40\n";

print "not " unless $rr->os eq $hinfo_os;
print "ok 41\n";

$rr2 = new Net::DNS::RR($rr->string);
print "not " unless $rr2->string eq $rr->string;
print "ok 42\n";

#------------------------------------------------------------------------------
# ISDN record
#------------------------------------------------------------------------------

$rr = $answer[5];
print "not " unless defined $rr;
print "ok 43\n";

print "not " unless $rr->name eq $name;
print "ok 44\n";

print "not " unless $rr->class eq $class;
print "ok 45\n";

print "not " unless $rr->type eq "ISDN";
print "ok 46\n";

print "not " unless $rr->ttl == $ttl;
print "ok 47\n";

print "not " unless $rr->address eq $isdn_address;
print "ok 48\n";

print "not " unless $rr->sa eq $isdn_sa;
print "ok 49\n";

$rr2 = new Net::DNS::RR($rr->string);
print "not " unless $rr2->string eq $rr->string;
print "ok 50\n";

#------------------------------------------------------------------------------
# MB record
#------------------------------------------------------------------------------

$rr = $answer[6];
print "not " unless defined $rr;
print "ok 51\n";

print "not " unless $rr->name eq $name;
print "ok 52\n";

print "not " unless $rr->class eq $class;
print "ok 53\n";

print "not " unless $rr->type eq "MB";
print "ok 54\n";

print "not " unless $rr->ttl == $ttl;
print "ok 55\n";

print "not " unless $rr->madname eq $mb_madname;
print "ok 56\n";

$rr2 = new Net::DNS::RR($rr->string);
print "not " unless $rr2->string eq $rr->string;
print "ok 57\n";

#------------------------------------------------------------------------------
# MG record
#------------------------------------------------------------------------------

$rr = $answer[7];
print "not " unless defined $rr;
print "ok 58\n";

print "not " unless $rr->name eq $name;
print "ok 59\n";

print "not " unless $rr->class eq $class;
print "ok 60\n";

print "not " unless $rr->type eq "MG";
print "ok 61\n";

print "not " unless $rr->ttl == $ttl;
print "ok 62\n";

print "not " unless $rr->mgmname eq $mg_mgmname;
print "ok 63\n";

$rr2 = new Net::DNS::RR($rr->string);
print "not " unless $rr2->string eq $rr->string;
print "ok 64\n";

#------------------------------------------------------------------------------
# MINFO record
#------------------------------------------------------------------------------

$rr = $answer[8];
print "not " unless defined $rr;
print "ok 65\n";

print "not " unless $rr->name eq $name;
print "ok 66\n";

print "not " unless $rr->class eq $class;
print "ok 67\n";

print "not " unless $rr->type eq "MINFO";
print "ok 68\n";

print "not " unless $rr->ttl == $ttl;
print "ok 69\n";

print "not " unless $rr->rmailbx eq $minfo_rmailbx;
print "ok 70\n";

print "not " unless $rr->emailbx eq $minfo_emailbx;
print "ok 71\n";

$rr2 = new Net::DNS::RR($rr->string);
print "not " unless $rr2->string eq $rr->string;
print "ok 72\n";

#------------------------------------------------------------------------------
# MR record
#------------------------------------------------------------------------------

$rr = $answer[9];
print "not " unless defined $rr;
print "ok 73\n";

print "not " unless $rr->name eq $name;
print "ok 74\n";

print "not " unless $rr->class eq $class;
print "ok 75\n";

print "not " unless $rr->type eq "MR";
print "ok 76\n";

print "not " unless $rr->ttl == $ttl;
print "ok 77\n";

print "not " unless $rr->newname eq $mr_newname;
print "ok 78\n";

$rr2 = new Net::DNS::RR($rr->string);
print "not " unless $rr2->string eq $rr->string;
print "ok 79\n";

#------------------------------------------------------------------------------
# MX record
#------------------------------------------------------------------------------

$rr = $answer[10];
print "not " unless defined $rr;
print "ok 80\n";

print "not " unless $rr->name eq $name;
print "ok 81\n";

print "not " unless $rr->class eq $class;
print "ok 82\n";

print "not " unless $rr->type eq "MX";
print "ok 83\n";

print "not " unless $rr->ttl == $ttl;
print "ok 84\n";

print "not " unless $rr->preference == $mx_preference;
print "ok 85\n";

print "not " unless $rr->exchange eq $mx_exchange;
print "ok 86\n";

$rr2 = new Net::DNS::RR($rr->string);
print "not " unless $rr2->string eq $rr->string;
print "ok 87\n";

#------------------------------------------------------------------------------
# NAPTR record
#------------------------------------------------------------------------------

$rr = $answer[11];
print "not " unless defined $rr;
print "ok 88\n";

print "not " unless $rr->name eq $name;
print "ok 89\n";

print "not " unless $rr->class eq $class;
print "ok 90\n";

print "not " unless $rr->type eq "NAPTR";
print "ok 91\n";

print "not " unless $rr->ttl == $ttl;
print "ok 92\n";

print "not " unless $rr->order == $naptr_order;
print "ok 93\n";

print "not " unless $rr->preference == $naptr_preference;
print "ok 94\n";

print "not " unless $rr->flags eq $naptr_flags;
print "ok 95\n";

print "not " unless $rr->service eq $naptr_service;
print "ok 96\n";

print "not " unless $rr->regexp eq $naptr_regexp;
print "ok 97\n";

print "not " unless $rr->replacement eq $naptr_replacement;
print "ok 98\n";

$rr2 = new Net::DNS::RR($rr->string);
print "not " unless $rr2->string eq $rr->string;
print "ok 99\n";

#------------------------------------------------------------------------------
# NS record
#------------------------------------------------------------------------------

$rr = $answer[12];
print "not " unless defined $rr;
print "ok 100\n";

print "not " unless $rr->name eq $name;
print "ok 101\n";

print "not " unless $rr->class eq $class;
print "ok 102\n";

print "not " unless $rr->type eq "NS";
print "ok 103\n";

print "not " unless $rr->ttl == $ttl;
print "ok 104\n";

print "not " unless $rr->nsdname eq $ns_nsdname;
print "ok 105\n";

$rr2 = new Net::DNS::RR($rr->string);
print "not " unless $rr2->string eq $rr->string;
print "ok 106\n";

#------------------------------------------------------------------------------
# NSAP record
#------------------------------------------------------------------------------

$rr = $answer[13];
print "not " unless defined $rr;
print "ok 107\n";

print "not " unless $rr->name eq $name;
print "ok 108\n";

print "not " unless $rr->class eq $class;
print "ok 109\n";

print "not " unless $rr->type eq "NSAP";
print "ok 110\n";

print "not " unless $rr->ttl == $ttl;
print "ok 111\n";

print "not " unless $rr->afi eq $nsap_afi;
print "ok 112\n";

print "not " unless $rr->idi eq $nsap_idi;
print "ok 113\n";

print "not " unless $rr->dfi eq $nsap_dfi;
print "ok 114\n";

print "not " unless $rr->aa eq $nsap_aa;
print "ok 115\n";

print "not " unless $rr->rd eq $nsap_rd;
print "ok 116\n";

print "not " unless $rr->area eq $nsap_area;
print "ok 117\n";

print "not " unless $rr->id eq $nsap_id;
print "ok 118\n";

print "not " unless $rr->sel eq $nsap_sel;
print "ok 119\n";

# $rr2 = new Net::DNS::RR($rr->string);
# print "not " unless $rr2->string eq $rr->string;
print "ok 120\n";

#------------------------------------------------------------------------------
# PTR record
#------------------------------------------------------------------------------

$rr = $answer[14];
print "not " unless defined $rr;
print "ok 121\n";

print "not " unless $rr->name eq $name;
print "ok 122\n";

print "not " unless $rr->class eq $class;
print "ok 123\n";

print "not " unless $rr->type eq "PTR";
print "ok 124\n";

print "not " unless $rr->ttl == $ttl;
print "ok 125\n";

print "not " unless $rr->ptrdname eq $ptr_ptrdname;
print "ok 126\n";

$rr2 = new Net::DNS::RR($rr->string);
print "not " unless $rr2->string eq $rr->string;
print "ok 127\n";

#------------------------------------------------------------------------------
# PX record
#------------------------------------------------------------------------------

$rr = $answer[15];
print "not " unless defined $rr;
print "ok 128\n";

print "not " unless $rr->name eq $name;
print "ok 129\n";

print "not " unless $rr->class eq $class;
print "ok 130\n";

print "not " unless $rr->type eq "PX";
print "ok 131\n";

print "not " unless $rr->ttl == $ttl;
print "ok 132\n";

print "not " unless $rr->preference == $px_preference;
print "ok 133\n";

print "not " unless $rr->map822 eq $px_map822;
print "ok 134\n";

print "not " unless $rr->mapx400 eq $px_mapx400;
print "ok 135\n";

$rr2 = new Net::DNS::RR($rr->string);
print "not " unless $rr2->string eq $rr->string;
print "ok 136\n";

#------------------------------------------------------------------------------
# RP record
#------------------------------------------------------------------------------

$rr = $answer[16];
print "not " unless defined $rr;
print "ok 137\n";

print "not " unless $rr->name eq $name;
print "ok 138\n";

print "not " unless $rr->class eq $class;
print "ok 139\n";

print "not " unless $rr->type eq "RP";
print "ok 140\n";

print "not " unless $rr->ttl == $ttl;
print "ok 141\n";

print "not " unless $rr->mbox eq $rp_mbox;
print "ok 142\n";

print "not " unless $rr->txtdname eq $rp_txtdname;
print "ok 143\n";

$rr2 = new Net::DNS::RR($rr->string);
print "not " unless $rr2->string eq $rr->string;
print "ok 144\n";

#------------------------------------------------------------------------------
# RT record
#------------------------------------------------------------------------------

$rr = $answer[17];
print "not " unless defined $rr;
print "ok 145\n";

print "not " unless $rr->name eq $name;
print "ok 146\n";

print "not " unless $rr->class eq $class;
print "ok 147\n";

print "not " unless $rr->type eq "RT";
print "ok 148\n";

print "not " unless $rr->ttl == $ttl;
print "ok 149\n";

print "not " unless $rr->preference == $rt_preference;
print "ok 150\n";

print "not " unless $rr->intermediate eq $rt_intermediate;
print "ok 151\n";

$rr2 = new Net::DNS::RR($rr->string);
print "not " unless $rr2->string eq $rr->string;
print "ok 152\n";

#------------------------------------------------------------------------------
# SOA record
#------------------------------------------------------------------------------

$rr = $answer[18];
print "not " unless defined $rr;
print "ok 153\n";

print "not " unless $rr->name eq $name;
print "ok 154\n";

print "not " unless $rr->class eq $class;
print "ok 155\n";

print "not " unless $rr->type eq "SOA";
print "ok 156\n";

print "not " unless $rr->ttl == $ttl;
print "ok 157\n";

print "not " unless $rr->mname eq $soa_mname;
print "ok 158\n";

print "not " unless $rr->rname eq $soa_rname;
print "ok 159\n";

print "not " unless $rr->serial == $soa_serial;
print "ok 160\n";

print "not " unless $rr->refresh == $soa_refresh;
print "ok 161\n";

print "not " unless $rr->retry == $soa_retry;
print "ok 162\n";

print "not " unless $rr->expire == $soa_expire;
print "ok 163\n";

print "not " unless $rr->minimum == $soa_minimum;
print "ok 164\n";

$rr2 = new Net::DNS::RR($rr->string);
print "not " unless $rr2->string eq $rr->string;
print "ok 165\n";

#------------------------------------------------------------------------------
# SRV record
#------------------------------------------------------------------------------

$rr = $answer[19];
print "not " unless defined $rr;
print "ok 166\n";

print "not " unless $rr->name eq $name;
print "ok 167\n";

print "not " unless $rr->class eq $class;
print "ok 168\n";

print "not " unless $rr->type eq "SRV";
print "ok 169\n";

print "not " unless $rr->ttl == $ttl;
print "ok 170\n";

print "not " unless $rr->priority == $srv_priority;
print "ok 171\n";

print "not " unless $rr->weight == $srv_weight;
print "ok 172\n";

print "not " unless $rr->port == $srv_port;
print "ok 173\n";

print "not " unless $rr->target eq $srv_target;
print "ok 174\n";

$rr2 = new Net::DNS::RR($rr->string);
print "not " unless $rr2->string eq $rr->string;
print "ok 175\n";

#------------------------------------------------------------------------------
# TXT record
#------------------------------------------------------------------------------

$rr = $answer[20];
print "not " unless defined $rr;
print "ok 176\n";

print "not " unless $rr->name eq $name;
print "ok 177\n";

print "not " unless $rr->class eq $class;
print "ok 178\n";

print "not " unless $rr->type eq "TXT";
print "ok 179\n";

print "not " unless $rr->ttl == $ttl;
print "ok 180\n";

print "not " unless $rr->txtdata eq $txt_txtdata;
print "ok 181\n";

$rr2 = new Net::DNS::RR($rr->string);
print "not " unless $rr2->string eq $rr->string;
print "ok 182\n";

#------------------------------------------------------------------------------
# X25 record
#------------------------------------------------------------------------------

$rr = $answer[21];
print "not " unless defined $rr;
print "ok 183\n";

print "not " unless $rr->name eq $name;
print "ok 184\n";

print "not " unless $rr->class eq $class;
print "ok 185\n";

print "not " unless $rr->type eq "X25";
print "ok 186\n";

print "not " unless $rr->ttl == $ttl;
print "ok 187\n";

print "not " unless $rr->psdn eq $x25_psdn;
print "ok 188\n";

$rr2 = new Net::DNS::RR($rr->string);
print "not " unless $rr2->string eq $rr->string;
print "ok 189\n";

#------------------------------------------------------------------------------
# LOC record
#------------------------------------------------------------------------------

$rr = $answer[22];
print "not " unless defined $rr;
print "ok 190\n";

print "not " unless $rr->name eq $name;
print "ok 191\n";

print "not " unless $rr->class eq $class;
print "ok 192\n";

print "not " unless $rr->type eq "LOC";
print "ok 193\n";

print "not " unless $rr->ttl == $ttl;
print "ok 194\n";

print "not " unless $rr->version eq $loc_version;
print "ok 195\n";

print "not " unless $rr->size == $loc_size;
print "ok 196\n";

print "not " unless $rr->horiz_pre == $loc_horiz_pre;
print "ok 197\n";

print "not " unless $rr->vert_pre == $loc_vert_pre;
print "ok 198\n";

print "not " unless $rr->latitude == $loc_latitude;
print "ok 199\n";

print "not " unless $rr->longitude == $loc_longitude;
print "ok 200\n";

print "not " unless $rr->altitude == $loc_altitude;
print "ok 201\n";

$rr2 = new Net::DNS::RR($rr->string);
print "not " unless $rr2->string eq $rr->string;
print "ok 202\n";
