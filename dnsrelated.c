#include "dnsrelated.h"

/* http://en.wikipedia.org/wiki/List_of_DNS_record_types */
const DNSTypeAndName DNSTypeList[] = {
	{1,		"IPv4 Address"},
	{28,	"IPv6 Address"},
	{18,	"AFSDB"},
	{42,	"APL"},
	{37,	"CERT"},
	{5,		"Canonical Name"},
	{49,	"DHCID"},
	{32769,	"DLV"},
	{39,	"DNAME"},
	{48,	"DNSKEY"},
	{43,	"DS"},
	{55,	"HIP"},
	{45,	"IPSECKEY"},
	{25,	"KEY"},
	{36,	"KX"},
	{29,	"LOC"},
	{15,	"MX"},
	{35,	"NAPTR"},
	{2,		"Name Server"},
	{47,	"NSEC"},
	{50,	"NSEC3"},
	{51,	"NSEC3PARAM"},
	{12,	"Domain pointer"},
	{46,	"RRSIG"},
	{17,	"RP"},
	{24,	"SIG"},
	{6,		"start of authority record"},
	{99,	"SPF"},
	{33,	"SRV"},
	{44,	"SSHFP"},
	{32768,	"TA"},
	{249,	"TKEY"},
	{250,	"TSIG"},
	{16,	"TXT"},
	{255,	"*"},
	{252,	"AXFR"},
	{251,	"IXFR"},
	{41,	"OPT"},
	{0,		NULL}
};

BOOL IsOneOfDNSTypes(int n)
{
	const DNSTypeAndName *Itr = DNSTypeList;

	while(Itr -> Num != 0)
	{
		if(Itr -> Num == n)
			return TRUE;

		++Itr;
	}

	return FALSE;
}

const char *DNSGetTypeName(_16BIT_UINT Num)
{
	int loop;

	for(loop = 0; loop < (sizeof(DNSTypeList) / sizeof(DNSTypeAndName)); ++loop)
	{
		if(DNSTypeList[loop].Num == Num)
			return DNSTypeList[loop].Name;
	}

	return "UNKNOWN";
}
