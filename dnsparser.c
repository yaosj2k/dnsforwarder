#include <stdio.h>
#include <memory.h>
#include <string.h>
#include "dnsparser.h"
#include "dnsgenerator.h"

const ElementDescriptor DNS_RECORD_A[] = {
	{DNS_IPV4_ADDR, "IPv4 Address"}
};

const ElementDescriptor DNS_RECORD_AAAA[] = {
	{DNS_IPV6_ADDR, "IPv6 Address"}
};

const ElementDescriptor DNS_RECORD_CNAME[] = {
	{DNS_LABELED_NAME,	"Canonical Name"}
};

const ElementDescriptor DNS_RECORD_SOA[] = {
	{DNS_LABELED_NAME,	"primary name server"},
	{DNS_LABELED_NAME,	"responsible mail addr"},
	{DNS_32BIT_UINT,	"serial"},
	{DNS_32BIT_UINT,	"refresh"},
	{DNS_32BIT_UINT,	"retry"},
	{DNS_32BIT_UINT,	"expire"},
	{DNS_32BIT_UINT,	"default TTL"},
};

const ElementDescriptor DNS_RECORD_DOMAIN_POINTER[] = {
	{DNS_LABELED_NAME,	"name"}
};

const ElementDescriptor DNS_RECORD_NAME_SERVER[] = {
	{DNS_LABELED_NAME,	"Name Server"}
};

static const struct _Type_Descriptor_DCount
{
	DNSRecordType			Type;
	const ElementDescriptor	*Descriptor;
	int						DCount;
}Type_Descriptor_DCount[] = {
	{DNS_TYPE_A,		DNS_RECORD_A,		NUM_OF_DNS_RECORD_A},
	{DNS_TYPE_AAAA,		DNS_RECORD_AAAA,	NUM_OF_DNS_RECORD_AAAA},
	{DNS_TYPE_CNAME,	DNS_RECORD_CNAME,	NUM_OF_DNS_RECORD_CNAME},
	{DNS_TYPE_SOA,		DNS_RECORD_SOA,		NUM_OF_DNS_RECORD_SOA},
	{DNS_TYPE_PTR,		DNS_RECORD_DOMAIN_POINTER,	NUM_OF_DNS_RECORD_DOMAIN_POINTER},
	{DNS_TYPE_NS,		DNS_RECORD_NAME_SERVER,	NUM_OF_DNS_RECORD_NAME_SERVER}

};

int DNSGetDescriptor(DNSRecordType Type, const ElementDescriptor **Buffer)
{
	int loop;
	for(loop = 0; loop != sizeof(Type_Descriptor_DCount) / sizeof(struct _Type_Descriptor_DCount); ++loop)
	{
		if(Type_Descriptor_DCount[loop].Type == Type)
		{
			*Buffer = Type_Descriptor_DCount[loop].Descriptor;
			return Type_Descriptor_DCount[loop].DCount;
		}
	}

	*Buffer = NULL;
	return 0;
}

BOOL DNSIsLabeledName(char *DNSBody, char *Start)
{

}

char *DNSJumpOverName(char *NameStart)
{
	while(1)
	{
		if((*(unsigned char *)NameStart) == 0)
			return NameStart + 1;

		if((*(unsigned char *)NameStart) == 192 /* 0x1100 0000 */)
			return NameStart + 2;

		++NameStart;
	}

	return NULL;
}

char *DNSGetQuestionRecordPosition(char *DNSBody, int Num)
{
	char *QR = DNSJumpHeader(DNSBody);

	if(Num > DNSGetQuestionCount(DNSBody))
		Num = DNSGetQuestionCount(DNSBody) + 1;

	if(Num < 1)
		return NULL;

	for(; Num != 1; --Num)
		QR = DNSJumpOverName(QR) + 4;

	return QR;
}

char *DNSGetAnswerRecordPosition(char *DNSBody, int Num)
{
	const char *SR = DNSJumpOverQuestionRecords(DNSBody);

	if(Num > DNSGetAnswerCount(DNSBody))
		Num = DNSGetAnswerCount(DNSBody) + 1;

	if(Num < 1)
		return NULL;

	for(; Num != 1; --Num)
		SR = DNSJumpOverName(SR) + 10 + DNSGetResourceDataLength(SR);

	return SR;
}

int DNSGetHostName(const char *DNSBody, const char *NameStart, char *buffer)
{
	int AllLabelLen = 0;
	int flag = 0;
	unsigned char LabelLen;

	while(1)
	{
		LabelLen = GET_8_BIT_U_INT(NameStart);

		if(LabelLen == 0) break;
		if(LabelLen > 192) return -1;

		if(flag == 0) ++AllLabelLen;

		if(LabelLen == 192 /* 0x1100 0000 */ /* 49152  0x1100 0000 0000 0000 */ )
		{
			NameStart = DNSBody + GET_8_BIT_U_INT(NameStart + 1);
			if(flag == 0)
			{
				++AllLabelLen;
				flag = 1;
			}
			continue;
		} else {
			for(++NameStart; LabelLen != 0; --LabelLen, ++NameStart)
			{
				*buffer++ = *NameStart;

				if(flag == 0)
					++AllLabelLen;
			}
			*buffer++ = '.';
			continue;
		}
	}

	if(AllLabelLen == 0)
		*buffer = '\0';
	else
		*(buffer - 1) = '\0';

	return AllLabelLen;
}


int DNSGetHostNameLength /* include terminated-zero */ (char *DNSBody, char *NameStart)
{
	int NameLen = 0;
	unsigned char LabelLen;

	while(TRUE)
	{
		LabelLen = GET_8_BIT_U_INT(NameStart);
		if(LabelLen == 0) break;
		if(LabelLen > 192) return -1;
		if(LabelLen == 192)
		{
			NameStart = DNSBody + GET_8_BIT_U_INT(NameStart + 1);
		} else {
			NameLen += LabelLen + 1;
			NameStart += LabelLen + 1;
		}
	}

	if(NameLen == 0)
		return 1;
	else
		return NameLen;
}

DNSDataInfo DNSParseData(char *DNSBody,
						char *DataBody,
						void *Buffer,
						int BufferLength,
						const ElementDescriptor *Descriptor,
						int CountOfDescriptor,
						int Num)
{
	DNSDataInfo Result = {DNS_DATA_TYPE_UNKNOWN, 0};

	if(Num > CountOfDescriptor)
		return Result;

	while(Num != 1)
	{
		switch(Descriptor -> element)
		{
			case DNS_LABELED_NAME:
				DataBody = DNSJumpOverName(DataBody);
				break;

			case DNS_IPV6_ADDR:
				DataBody += 16;
				break;

			case DNS_IPV4_ADDR:
			case DNS_32BIT_UINT:
				DataBody += 4;
				break;

			case DNS_16BIT_UINT:
				DataBody += 2;
				break;

			case DNS_8BIT_UINT:
				DataBody += 1;
				break;

			default:
				return Result;
				break;
		}

		--Num;
		++Descriptor;
	}

	switch(Descriptor -> element)
	{
		case DNS_LABELED_NAME:
			if(BufferLength < DNSGetHostNameLength(DNSBody, DataBody))
				break;

			Result.DataLength = DNSGetHostNameLength(DNSBody, DataBody);
			DNSGetHostName(DNSBody, DataBody, (char *)Buffer);
			Result.DataType = DNS_DATA_TYPE_STRING;
			break;

		case DNS_32BIT_UINT:
			{
				_32BIT_UINT Tmp = GET_32_BIT_U_INT(DataBody);
				if(BufferLength < 4)
					break;
				memcpy(Buffer, &Tmp, 4);
				Result.DataLength = 4;
				Result.DataType = DNS_DATA_TYPE_UINT;
			}
			break;

		case DNS_16BIT_UINT:
			{
				_16BIT_UINT Tmp = GET_16_BIT_U_INT(DataBody);
				if(BufferLength < 2)
					break;
				memcpy(Buffer, &Tmp, 2);
				Result.DataLength = 2;
				Result.DataType = DNS_DATA_TYPE_UINT;
			}
			break;

		case DNS_8BIT_UINT:
			if(BufferLength < 1)
				break;
			*(char *)Buffer = *DataBody;
			Result.DataLength = 1;
			Result.DataType = DNS_DATA_TYPE_UINT;
			break;


		case DNS_IPV4_ADDR:
			if(BufferLength < 16)
				break;
			Result.DataLength =
			sprintf((char *)Buffer, "%u.%u.%u.%u",	GET_8_BIT_U_INT(DataBody),
											GET_8_BIT_U_INT(DataBody + 1),
											GET_8_BIT_U_INT(DataBody + 2),
											GET_8_BIT_U_INT(DataBody + 3)
				);
			Result.DataType = DNS_DATA_TYPE_STRING;
			break;

		case DNS_IPV6_ADDR:
			if(BufferLength < 40)
				break;
			Result.DataLength =
			sprintf((char *)Buffer, "%x:%x:%x:%x:%x:%x:%x:%x",	GET_16_BIT_U_INT(DataBody),
														GET_16_BIT_U_INT(DataBody + 2),
														GET_16_BIT_U_INT(DataBody + 4),
														GET_16_BIT_U_INT(DataBody + 6),
														GET_16_BIT_U_INT(DataBody + 8),
														GET_16_BIT_U_INT(DataBody + 10),
														GET_16_BIT_U_INT(DataBody + 12),
														GET_16_BIT_U_INT(DataBody + 14)

				);
			Result.DataType = DNS_DATA_TYPE_STRING;
			break;

		default:
			break;
	}
	return Result;
}

char *GetAnswer(char *DNSBody, char *DataBody, char *Buffer, DNSRecordType ResourceType)
{
	int loop, loop2;

	if( Buffer == NULL )
		return NULL;

	for(loop = 0;
		loop != sizeof(Type_Descriptor_DCount) / sizeof(struct _Type_Descriptor_DCount);
		++loop
		)
	{
		if( Type_Descriptor_DCount[loop].Type == ResourceType )
			break;
	}

	if(loop < sizeof(Type_Descriptor_DCount) / sizeof(struct _Type_Descriptor_DCount))
	{
		char		InnerBuffer[512];
		DNSDataInfo	Data;

		Buffer += sprintf(Buffer, "   %s:", DNSGetTypeName(ResourceType));

		if(Type_Descriptor_DCount[loop].DCount != 1)
		{
			Buffer += sprintf(Buffer, "\n");
		}

		for(loop2 = 0; loop2 != Type_Descriptor_DCount[loop].DCount; ++loop2)
		{
			Data = DNSParseData(DNSBody,
								DataBody,
								InnerBuffer,
								sizeof(InnerBuffer),
								Type_Descriptor_DCount[loop].Descriptor,
								Type_Descriptor_DCount[loop].DCount,
								loop2 + 1);

			if( Type_Descriptor_DCount[loop].DCount != 1 )
			{
				if( Type_Descriptor_DCount[loop].Descriptor[loop2].description != NULL )
					Buffer += sprintf(Buffer, "      %s:", Type_Descriptor_DCount[loop].Descriptor[loop2].description);
			}

			switch(Data.DataType)
			{
				case DNS_DATA_TYPE_INT:
					if(Data.DataLength == 1)
						Buffer += sprintf(Buffer, "%d", (int)*(char *)InnerBuffer);

					if(Data.DataLength == 2)
						Buffer += sprintf(Buffer, "%d", (int)*(_16BIT_INT *)InnerBuffer);

					if(Data.DataLength == 4)
						Buffer += sprintf(Buffer, "%u", *(_32BIT_INT *)InnerBuffer);

					break;

				case DNS_DATA_TYPE_UINT:
					if(Data.DataLength == 1)
						Buffer += sprintf(Buffer, "%d", (int)*(unsigned char *)InnerBuffer);

					if(Data.DataLength == 2)
						Buffer += sprintf(Buffer, "%d", (int)*(_16BIT_UINT *)InnerBuffer);

					if(Data.DataLength == 4)
						Buffer += sprintf(Buffer, "%u", *(_32BIT_UINT *)InnerBuffer);

					break;

				case DNS_DATA_TYPE_STRING:
					Buffer += sprintf(Buffer, "%s", InnerBuffer);
					break;

				default:
					break;
			}

			if(Type_Descriptor_DCount[loop].Descriptor[loop2].description != NULL)
				Buffer += sprintf(Buffer, "\n");
		}
	}
	return Buffer;
}

char *GetAllAnswers(char *DNSBody, char *Buffer)
{
	int		AnswerCount;
	char	*Itr;
	int		loop	=	0;
	int		UsedCount;
	DNSRecordType	ResourceType;

	AnswerCount = DNSGetAnswerCount(DNSBody);

	if( AnswerCount == 0 )
	{
		strcpy(Buffer, "   Nothing.\n");
		return Buffer + 12;
	}

	UsedCount = AnswerCount > 6 ? 6 : AnswerCount;

	while(loop != UsedCount){
		Itr = DNSGetAnswerRecordPosition(DNSBody, loop + 1);

		ResourceType = (DNSRecordType)DNSGetRecordType(Itr);

		Buffer = GetAnswer(DNSBody, DNSGetResourceDataPos(Itr), Buffer, ResourceType);

		++loop;
	}
	if( AnswerCount > 6 )
	{
		Buffer += sprintf(Buffer, "   And %d More ...\n", AnswerCount - 6);
	}
	return Buffer;
}

int DNSExpand(char *DNSBody, int BufferLength)
{

}

void DNSCopyLable(char *DNSBody, char *here, char *src)
{
	while( 1 )
	{
		if( (unsigned char)(*src) == 0xC0 )
		{
			src = DNSBody + *(src + 1);

		} else {
			*here = *src;

			if( *src == 0 )
			{
				break;
			}

			++here;
			++src;
		}
	}
}

int DNSExpandCName_MoreSpaceNeeded(const char *DNSBody)
{
	int				AnswerCount	=	DNSGetAnswerCount(DNSBody);
	int				Itr	=	1;
	int				MoreSpaceNeeded = 0;
	char			*Answer;
	DNSRecordType	Type;
	char			*Resource;
	int				ResourceLength;

	int				NameLength;

	if( AnswerCount < 1 )
	{
		return 0;
	}

	do
	{
		Answer = DNSGetAnswerRecordPosition(DNSBody, Itr);

		Type = DNSGetRecordType(Answer);
		if( Type == DNS_TYPE_CNAME )
		{
			ResourceLength = DNSGetResourceDataLength(Answer);
			Resource = DNSGetResourceDataPos(Answer);
			NameLength = DNSGetHostNameLength(DNSBody, Resource);

			MoreSpaceNeeded += (NameLength + 1) - ResourceLength;
		}

		++Itr;

	}while( Itr <= AnswerCount );

	return MoreSpaceNeeded;
}

/* You should meke sure there is no additional record and nameserver record */
void DNSExpandCName(char *DNSBody)
{
	int				AnswerCount	=	DNSGetAnswerCount(DNSBody);
	int				Itr	=	1;
	char			*Answer;
	DNSRecordType	Type;
	char			*Resource;
	int				ResourceLength;

	int				NameLength;
	char			*NameEnd; /* After terminated-zero */

	char			*DNSEnd;


	if( AnswerCount < 1 )
	{
		return;
	}

	do
	{
		Answer = DNSGetAnswerRecordPosition(DNSBody, Itr);

		Type = DNSGetRecordType(Answer);
		if( Type == DNS_TYPE_CNAME )
		{
			ResourceLength = DNSGetResourceDataLength(Answer);
			Resource = DNSGetResourceDataPos(Answer);
			NameLength = DNSGetHostNameLength(DNSBody, Resource);

			NameEnd = Resource + ResourceLength;

			DNSEnd = DNSGetAnswerRecordPosition(DNSBody, AnswerCount + 1);

			SET_16_BIT_U_INT(Resource - 2, NameLength + 1);

			memmove(Resource + NameLength + 1, NameEnd, DNSEnd - NameEnd);

			DNSCopyLable(DNSBody, Resource, Resource);
		}

		++Itr;

	}while( Itr <= AnswerCount );
}

void DNSParser(char *dns_over_tcp, char *buffer){
	char *dnsovertcp	=	dns_over_tcp;
	char InnerBuffer[128]		=	{0};
	unsigned short qc, ac;

	buffer += sprintf(buffer, "TCPLength:%hu\n", DNSGetTCPLength(DNSGetDNSBody(dnsovertcp)));

	buffer += sprintf(buffer, "QueryIdentifier:%hu\n", DNSGetQueryIdentifier(DNSGetDNSBody(dnsovertcp)));

	buffer += sprintf(buffer, "Flags:%x\n", DNSGetFlags(DNSGetDNSBody(dnsovertcp)));

	qc = DNSGetQuestionCount(DNSGetDNSBody(dnsovertcp));
	buffer += sprintf(buffer, "QuestionCount:%hu\n", qc);

	ac = DNSGetAnswerCount(DNSGetDNSBody(dnsovertcp));
	buffer += sprintf(buffer, "AnswerCount:%hu\n", ac);

	buffer += sprintf(buffer, "NameServerCount:%hu\n", DNSGetNameServerCount(DNSGetDNSBody(dnsovertcp)));

	buffer += sprintf(buffer, "AdditionalCount:%hu\n", DNSGetAdditionalCount(DNSGetDNSBody(dnsovertcp)));

	dnsovertcp = DNSJumpHeader(DNSGetDNSBody(dns_over_tcp));

	for(; qc != 0; --qc){
		DNSGetHostName(dns_over_tcp + 2, dnsovertcp, InnerBuffer);
		buffer += sprintf(buffer, "QuestionName:%s\n", InnerBuffer);

		buffer += sprintf(buffer, "QuestionType:%hu\n", DNSGetRecordType(dnsovertcp));

		buffer += sprintf(buffer, "QuestionClass:%hu\n", DNSGetRecordClass(dnsovertcp));
	}

	dnsovertcp = DNSJumpOverQuestionRecords(DNSGetDNSBody(dns_over_tcp));

	while(ac != 0){
		unsigned short rt, dl;
		dnsovertcp = DNSGetAnswerRecordPosition(DNSGetDNSBody(dns_over_tcp), DNSGetAnswerCount(DNSGetDNSBody(dns_over_tcp)) - ac + 1);

		DNSGetHostName(dns_over_tcp + 2, dnsovertcp, InnerBuffer);
		buffer += sprintf(buffer, "ResourceName:%s\n", InnerBuffer);

		rt = DNSGetRecordType(dnsovertcp);
		buffer += sprintf(buffer, "ResourceType:%hu\n", rt);

		buffer += sprintf(buffer, "ResourceClass:%hu\n", DNSGetRecordClass(dnsovertcp));

		buffer += sprintf(buffer, "TimeToLive:%u\n", (unsigned int)DNSGetTTL(dnsovertcp));

		dl = DNSGetResourceDataLength(dnsovertcp);
		buffer += sprintf(buffer, "ResourceDataLength:%hu\n", dl);

		dnsovertcp = DNSGetResourceDataPos(dnsovertcp);
		switch(rt){
			case DNS_TYPE_A: /* A, IPv4 address */
				buffer += sprintf(buffer, "IPv4Addres:%d.%d.%d.%d\n", GET_8_BIT_U_INT(dnsovertcp), GET_8_BIT_U_INT(dnsovertcp + 1), GET_8_BIT_U_INT(dnsovertcp + 2), GET_8_BIT_U_INT(dnsovertcp + 3));
				break;
			case DNS_TYPE_AAAA: /* AAAA, IPv6 address */
				buffer += sprintf(buffer, "IPv6Addres:%x:%x:%x:%x:%x:%x:%x:%x\n",
					GET_16_BIT_U_INT(dnsovertcp), GET_16_BIT_U_INT(dnsovertcp + 2), GET_16_BIT_U_INT(dnsovertcp + 4), GET_16_BIT_U_INT(dnsovertcp + 6),
					GET_16_BIT_U_INT(dnsovertcp + 8), GET_16_BIT_U_INT(dnsovertcp + 10), GET_16_BIT_U_INT(dnsovertcp + 12), GET_16_BIT_U_INT(dnsovertcp + 14)
					);
				break;
			case DNS_TYPE_CNAME: /* CNAME */
				DNSGetHostName(dns_over_tcp + 2, dnsovertcp, InnerBuffer);
				buffer += sprintf(buffer, "CName:%s\n", InnerBuffer);
				break;
			default:
				break;
		}
		dnsovertcp = DNSGetAnswerRecordPosition(DNSGetDNSBody(dns_over_tcp), DNSGetAnswerCount(dns_over_tcp) - ac + 1);
		--ac;
	}
}

#ifdef AAAAAAAAAAAA

void DNSParser(const char *dns_over_tcp, char *buffer){
	char *orig = buffer;
	char *dnsovertcp = dns_over_tcp;
	char InnerBuffer[128];
	unsigned short qc, ac;

	buffer += sprintf(buffer, "TCPLength:%hu\n", GET_16_BIT_U_INT(dnsovertcp));

	dnsovertcp += 2; /* sizeof(unsigned short) */
	buffer += sprintf(buffer, "QueryIdentifier:%hu\n", GET_16_BIT_U_INT(dnsovertcp));

	dnsovertcp += 2; /* sizeof(unsigned short) */
	buffer += sprintf(buffer, "Flags:%x\n", GET_16_BIT_U_INT(dnsovertcp));

	dnsovertcp += 2; /* sizeof(unsigned short) */
	buffer += sprintf(buffer, "QuestionCount:%hu\n", GET_16_BIT_U_INT(dnsovertcp));
	qc = GET_16_BIT_U_INT(dnsovertcp);

	dnsovertcp += 2; /* sizeof(unsigned short) */
	buffer += sprintf(buffer, "AnswerCount:%hu\n", GET_16_BIT_U_INT(dnsovertcp));
	ac = GET_16_BIT_U_INT(dnsovertcp);

	dnsovertcp += 2; /* sizeof(unsigned short) */
	buffer += sprintf(buffer, "NameServerCount:%hu\n", GET_16_BIT_U_INT(dnsovertcp));

	dnsovertcp += 2; /* sizeof(unsigned short) */
	buffer += sprintf(buffer, "AdditionalCount:%hu\n", GET_16_BIT_U_INT(dnsovertcp));

	dnsovertcp += 2; /* sizeof(unsigned short) */

	for(; qc != 0; --qc){
		dnsovertcp += DNSGetHostName(dns_over_tcp + 2, dnsovertcp, InnerBuffer);
		buffer += sprintf(buffer, "QuestionName:%s\n", InnerBuffer);

		buffer += sprintf(buffer, "QuestionType:%hu\n", GET_16_BIT_U_INT(dnsovertcp));

		dnsovertcp += 2; /* sizeof(unsigned short) */
		buffer += sprintf(buffer, "QuestionClass:%hu\n", GET_16_BIT_U_INT(dnsovertcp));

		dnsovertcp += 2; /* sizeof(unsigned short) */
	}

	for(; ac != 0; --ac){
		unsigned short rt, dl;
		dnsovertcp += DNSGetHostName(dns_over_tcp + 2, dnsovertcp, InnerBuffer);
		buffer += sprintf(buffer, "ResourceName:%s\n", InnerBuffer);


		buffer += sprintf(buffer, "ResourceType:%hu\n", GET_16_BIT_U_INT(dnsovertcp));
		rt = GET_16_BIT_U_INT(dnsovertcp);

		dnsovertcp += 2; /* sizeof(unsigned short) */
		buffer += sprintf(buffer, "ResourceClass:%hu\n", GET_16_BIT_U_INT(dnsovertcp));

		dnsovertcp += 2; /* sizeof(unsigned short) */
		buffer += sprintf(buffer, "TimeToLive:%u\n", GET_32_BIT_U_INT(dnsovertcp));

		dnsovertcp += 4; /* sizeof(unsigned int) */
		buffer += sprintf(buffer, "ResourceDataLength:%hu\n", GET_16_BIT_U_INT(dnsovertcp));
		dl = GET_16_BIT_U_INT(dnsovertcp);

		dnsovertcp += 2; /* sizeof(unsigned short) */
		switch(rt){
			case DNS_TYPE_A: /* A, IPv4 address */
				buffer += sprintf(buffer, "IPv4Addres:%d.%d.%d.%d\n", GET_8_BIT_U_INT(dnsovertcp), GET_8_BIT_U_INT(dnsovertcp + 1), GET_8_BIT_U_INT(dnsovertcp + 2), GET_8_BIT_U_INT(dnsovertcp + 3));
				break;
			case DNS_TYPE_AAAA: /* AAAA, IPv6 address */
				buffer += sprintf(buffer, "IPv6Addres:%x:%x:%x:%x:%x:%x:%x:%x \n",
					GET_16_BIT_U_INT(dnsovertcp), GET_16_BIT_U_INT(dnsovertcp + 2), GET_16_BIT_U_INT(dnsovertcp + 4), GET_16_BIT_U_INT(dnsovertcp + 6),
					GET_16_BIT_U_INT(dnsovertcp + 8), GET_16_BIT_U_INT(dnsovertcp + 10), GET_16_BIT_U_INT(dnsovertcp + 12), GET_16_BIT_U_INT(dnsovertcp + 14)
					);
				break;
			case DNS_TYPE_CNAME: /* CNAME */
				DNSGetHostName(dns_over_tcp + 2, dnsovertcp, InnerBuffer);
				buffer += sprintf(buffer, "CName:%s\n", InnerBuffer);
				break;
			default:
				break;
		}
		dnsovertcp += dl;
	}
}

#endif
