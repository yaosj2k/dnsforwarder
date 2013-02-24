#ifndef _DNS_PARSER_H_
#define _DNS_PARSER_H_

#include <limits.h>
#include "common.h"
#include "dnsrelated.h"

#define GET_16_BIT_U_INT(ptr)	(ntohs(*(_16BIT_INT *)(ptr)))
#define GET_32_BIT_U_INT(ptr)		(ntohl(*(_32BIT_INT *)(ptr)))
#define GET_8_BIT_U_INT(ptr)		(*(unsigned char*)(ptr))

#define DNS_HEADER_LENGTH	12

/* Handle DNS header*/
#define DNSGetTCPLength(dns_over_tcp_ptr)	GET_16_BIT_U_INT(dns_over_tcp_ptr)

#define DNSGetDNSBody(dns_over_tcp_ptr)		((char *)(dns_over_tcp_ptr) + 2)

#define DNSGetQueryIdentifier(dns_body)		GET_16_BIT_U_INT((char *)(dns_body))

#define DNSGetFlags(dns_body)				GET_16_BIT_U_INT((char *)(dns_body) + 2)

#define DNSGetQuestionCount(dns_body)		GET_16_BIT_U_INT((char *)(dns_body) + 4)

#define DNSGetAnswerCount(dns_body)			GET_16_BIT_U_INT((char *)(dns_body) + 6)

#define DNSGetNameServerCount(dns_body)		GET_16_BIT_U_INT((char *)(dns_body) + 8)

#define DNSGetAdditionalCount(dns_body)		GET_16_BIT_U_INT((char *)(dns_body) + 10)

#define DNSJumpHeader(dns_body)				((char *)(dns_body) + DNS_HEADER_LENGTH)

/* Handle question record */
char *DNSGetQuestionRecordPosition(char *DNSBody, int Num);

#define DNSJumpOverQuestionRecords(dns_body)	DNSGetQuestionRecordPosition((dns_body), DNSGetQuestionCount(dns_body) + 1)

/* Handle resource\answer record */
char *DNSGetAnswerRecordPosition(char *DNSBody, int Num);

#define DNSGetTTL(ans_start_ptr)				GET_32_BIT_U_INT(DNSJumpOverName(ans_start_ptr) + 4)

#define DNSGetResourceDataLength(ans_start_ptr)	GET_16_BIT_U_INT(DNSJumpOverName(ans_start_ptr) + 8)

#define DNSGetResourceDataPos(ans_start_ptr)	(DNSJumpOverName(ans_start_ptr) + 10)

#define DNSJumpOverAnswerRecords(dns_body)		DNSGetAnswerRecordPosition((dns_body), DNSGetAnswerCount(dns_body) + 1)

#define DNSGetARecordLength(record_ptr)			(strlen(record_ptr) + 1 + 10 + DNSGetResourceDataLength(record_ptr))

/* Common */
char *DNSJumpOverName(char *NameStart);

int DNSGetHostName(const char *DNSBody, const char *NameStart, char *buffer);

int DNSGetHostNameLength(char *DNSBody, char *NameStart);

#define DNSGetRecordType(rec_start_ptr)		GET_16_BIT_U_INT(DNSJumpOverName(rec_start_ptr))

#define DNSGetRecordClass(rec_start_ptr)	GET_16_BIT_U_INT(DNSJumpOverName(rec_start_ptr) + 2)

int DNSExpandCName_MoreSpaceNeeded(const char *DNSBody);

void DNSExpandCName(char *DNSBody);

typedef enum _RecordElement{
	DNS_UNKNOWN  = 0,
	DNS_LABELED_NAME,
	DNS_32BIT_UINT,
	DNS_16BIT_UINT,
	DNS_8BIT_UINT,
	DNS_PLANT_TEXT,

	DNS_IPV4_ADDR = (INT_MAX / 4),
	DNS_IPV6_ADDR,
}RecordElement;

typedef struct _ElementDescriptor{
	RecordElement	element;
	char			*description;
}ElementDescriptor;

extern const ElementDescriptor DNS_RECORD_A[];
#define	NUM_OF_DNS_RECORD_A	1

extern const ElementDescriptor DNS_RECORD_AAAA[];
#define	NUM_OF_DNS_RECORD_AAAA	1

extern const ElementDescriptor DNS_RECORD_CNAME[];
#define	NUM_OF_DNS_RECORD_CNAME	1

extern const ElementDescriptor DNS_RECORD_SOA[];
#define	NUM_OF_DNS_RECORD_SOA	7

extern const ElementDescriptor DNS_RECORD_DOMAIN_POINTER[];
#define	NUM_OF_DNS_RECORD_DOMAIN_POINTER	1

extern const ElementDescriptor DNS_RECORD_NAME_SERVER[];
#define	NUM_OF_DNS_RECORD_NAME_SERVER	1

int DNSGetDescriptor(DNSRecordType Type, const ElementDescriptor **Buffer);

#ifdef HOST_BIG_ENDIAN
/* DNSMessageFlags, on offset 2(bytes) of a DNS message body, is 2 bytes length.
 * For details: http://www.freesoft.org/CIE/RFC/1035/40.htm */
typedef struct _DNSMessageProperties{
	_16BIT_UINT	Direction	:	1; /* query (0), or response (1) */

	/* Type:
	 * 0	a standard query (QUERY).
	 * 1	an inverse query (IQUERY).
	 * 2	a server status request (STATUS).
	 * 3-15	reserved for future use  */
	_16BIT_UINT Type			:	4;

	_16BIT_UINT	AuthoritativeAnswer:1;

	_16BIT_UINT	TrunCation		:	1;

	_16BIT_UINT	RecursionDesired:	1; /* 0 no, 1 yes */

	_16BIT_UINT	RecursionAvailable:	1; /* 0 no, 1 yes */

	_16BIT_UINT	Unused			:	3;

	/* ResponseCode:
	 * 0	No error condition.
	 * 1	Format error - The name server was unable to interpret the query.
	 * 2	Server failure - The name server was unable to process this query due to a problem with the name server.
	 * 3	Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.
	 * 4	Not Implemented - The name server does not support the requested kind of query.
	 * 5	Refused - The name server refuses to perform the specified operation for policy reasons. For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data.
	 * 6-15	Reserved for future use. */
	_16BIT_UINT	ResponseCode	:	4;

}DNSFlags;
#else
typedef struct _DNSMessageProperties{
	/* ResponseCode:
	 * 0	No error condition.
	 * 1	Format error - The name server was unable to interpret the query.
	 * 2	Server failure - The name server was unable to process this query due to a problem with the name server.
	 * 3	Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.
	 * 4	Not Implemented - The name server does not support the requested kind of query.
	 * 5	Refused - The name server refuses to perform the specified operation for policy reasons. For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data.
	 * 6-15	Reserved for future use. */
	_16BIT_UINT	ResponseCode	:	4;

	_16BIT_UINT	Unused			:	3;

	_16BIT_UINT	RecursionAvailable:	1; /* 0 no, 1 yes */

	_16BIT_UINT	RecursionDesired:	1; /* 0 no, 1 yes */

	_16BIT_UINT	TrunCation		:	1;

	_16BIT_UINT	AuthoritativeAnswer:1;

	/* Type:
	 * 0	a standard query (QUERY).
	 * 1	an inverse query (IQUERY).
	 * 2	a server status request (STATUS).
	 * 3-15	reserved for future use  */
	_16BIT_UINT Type			:	4;

	_16BIT_UINT	Direction		:	1; /* query (0), or response (1) */

}DNSFlags;
#endif

typedef struct _DNSHeader{
	_16BIT_UINT		Identifier;
	DNSFlags		Flags;
	_16BIT_UINT		QuestionCount;
	_16BIT_UINT		AnswerCount;
	_16BIT_UINT		NameServerCount;
	_16BIT_UINT		AdditionalCount;
}DNSHeader;

#define DNSGetHeader(dns_body_ptr)	((DNSHeader *)(dns_body_ptr))

/* DNS_DataType and DNSDataInfo are for DNSParseData() */
typedef enum _DNS_DataType{
	DNS_DATA_TYPE_UNKNOWN = 0,
	DNS_DATA_TYPE_INT,
	DNS_DATA_TYPE_UINT,
	DNS_DATA_TYPE_STRING
}DNS_DataType;

typedef struct _DNSDataInfo{
	DNS_DataType	DataType;
	int				DataLength;
}DNSDataInfo;

DNSDataInfo DNSParseData(char *DNSBody,
						char *DataBody,
						void *Buffer,
						int BufferLength,
						const ElementDescriptor *Descriptor,
						int CountOfDescriptor,
						int Num);

/* Convert a DNS message to text */
char *GetAnswer(char *DNSBody, char *DataBody, char *Buffer, DNSRecordType ResourceType);

char *GetAllAnswers(char *DNSBody, char *Buffer);

void DNSParser(char *dns_over_tcp, char *buffer);

#endif /* _DNS_PARSER_H_ */
