/*
 * $Id: DNS.xs,v 1.9 2003/06/01 23:18:57 ctriv Exp $
 *
 */

#ifdef _HPUX_SOURCE
#define _SYS_MAGIC_INCLUDED
#endif
 
 
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h> 


/*
 * int dn_expand(const uchar_t *msg,  const	 uchar_t  *eomorig,
 *	 uchar_t *comp_dn, char exp_dn, int length); 
 *
 *	   
 * dn_expand
 *	 dn_expand() expands the compressed domain name	 given by the
 *	 pointer comp _dn into a full domain name. Expanded names are
 *	 converted to upper case. The compressed name is contained in
 *	 a	query or reply message; msg is a pointer to the beginning
 *	 of that message. Expanded names are  stored  in  the  buffer
 *	 referenced by the exp_dn buffer of size length , which should
 *	 be large enough to hold the expanded result.
 *
 *	 dn_expand() returns the size of the compressed name,  or  -1
 *	 if there was an error. 
 */

MODULE = Net::DNS PACKAGE = Net::DNS::Packet

void
dn_expand_XS(buffer, offset) 
	SV * buffer
	int offset

  PROTOTYPE: $$		
  PPCODE:
	STRLEN len;
	char * buf;
	char name[MAXDNAME];
	int pos;
	
	if (SvROK(buffer)) 
		buffer = SvRV(buffer);
	
	
	buf = SvPV(buffer, len);
	pos = dn_expand(buf, buf+len, buf+offset, &name[0], MAXDNAME);
	
	EXTEND(SP, 2);
	
	if (pos < 0) {
		PUSHs(sv_2mortal(newSVsv(&PL_sv_undef)));
		PUSHs(sv_2mortal(newSVsv(&PL_sv_undef)));
	} else {
		PUSHs(sv_2mortal(newSVpv(name, 0)));
		PUSHs(sv_2mortal(newSViv(pos + offset)));
	}
	
	XSRETURN(2);
 
