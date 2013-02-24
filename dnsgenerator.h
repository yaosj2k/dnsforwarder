#ifndef _DNS_GENERATOR_H_
#define _DNS_GENERATOR_H_

#include <string.h>
//#include "common.h"
#include "dnsparser.h"

#define SET_16_BIT_U_INT(here, val)	(*(_16BIT_UINT *)(here) = htons((_16BIT_UINT)(val)))
#define SET_32_BIT_U_INT(here, val)	(*(_32BIT_UINT *)(here) = htonl((_32BIT_UINT)(val)))

/* Handle DNS header*/
#define DNSSetQueryIdentifier(dns_start, QId)	SET_16_BIT_U_INT((char *)(dns_start), QId)

#define DNSSetFlags(dns_start, Flags)			SET_16_BIT_U_INT((char *)(dns_start) + 2, Flags)

#define DNSSetQuestionCount(dns_start, QC)		SET_16_BIT_U_INT((char *)(dns_start) + 4, QC)

#define DNSSetAnswerCount(dns_start, AnC)		SET_16_BIT_U_INT((char *)(dns_start) + 6, AnC)

#define DNSSetNameServerCount(dns_start, ASC)	SET_16_BIT_U_INT((char *)(dns_start) + 8, ASC)

#define DNSSetAdditionalCount(dns_start, AdC)	SET_16_BIT_U_INT((char *)(dns_start) + 10, AdC)

char *DNSLabelizedName(__inout char *Origin, __in int OriginSpaceLength);

int DNSCompress(__inout char *DNSBody, __in int DNSBodyLength);

int DNSGenerateData(__in char *Data,
					__out void *Buffer,
					__in int BufferLength,
					__in const ElementDescriptor *Descriptor
					);

char *DNSGenHeader(	__out char			*Buffer,
					__in unsigned short	QueryIdentifier,
					__in DNSFlags		Flags,
					__in unsigned short	QuestionCount,
					__in unsigned short	AnswerCount,
					__in unsigned short	NameServerCount,
					__in unsigned short	AdditionalCount
					);

int DNSGenQuestionRecord(__out char		*Buffer,
						   __in int			BufferLength,
						   __inout char		*Name,
						   __in int			NameSpaceLength,
						   __in _16BIT_UINT	Type,
						   __in _16BIT_UINT	Class
						   );

int DNSGenResourceRecord(	__out char			*Buffer,
							__in int			BufferLength,
							__in char			*Name,
							__in _16BIT_UINT	Type,
							__in _16BIT_UINT	Class,
							__in _32BIT_UINT	TTL,
							__in const void		*Data,
							__in _16BIT_UINT	DataLength,
							__in BOOL			LablelizedData
						   );


#define DNSSetName(here, labeled_name)			(memcpy((here), (labeled_name), strlen(labeled_name) + 1), \
													((char *)here) + strlen(labeled_name) + 1)

#define DNSSetResourceDataLength(ans_start_ptr, len)	SET_16_BIT_U_INT(DNSJumpOverName(ans_start_ptr) + 8, len)

int DNSAppendAnswerRecord(__inout char *OriginBody, __in char *Record, __in int RecordLength);

#endif /* _DNS_GENERATOR_H_ */
