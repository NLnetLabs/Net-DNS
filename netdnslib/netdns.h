#define TESTVAL 4
extern double foo(int, long, const char*);





/*
 * Defines for handling compressed domain names
 */
#define INDIR_MASK 0xc0

/* Note: MAXDNAME is the size of a DNAME in PRESENTATION FORMAT.
 *  Each character in the label may need 4 characters in presentation format
 * think \002.\003\004.example.com
 * Hmmm 1010 is just a bit oversized 
 */

#define MAXDNAME 1010

int dn_expand( char *msg,  char *eomorig,
	       char *comp_dn,  char *exp_dn,
	      size_t length);

