#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "querydnslistenudp.h"
#include "querydnsbase.h"
#include "dnsrelated.h"
#include "dnsparser.h"
#include "common.h"
#include "utils.h"
#include "stringlist.h"
#include "excludedlist.h"

#define _SendTo(...)	GET_MUTEX(SendToMutex); sendto(__VA_ARGS__); RELEASE_MUTEX(SendToMutex);

/* Variables */
static BOOL			Inited = FALSE;

static MutexHandle	ListenMutex;
static MutexHandle	SendToMutex;

static SOCKET		ListenSocketUDP;

static sa_family_t	Family;

static ThreadHandle	*Threads;
static int			ThreadCount;

static int			MaximumMessageSize;

/* Functions */
int QueryDNSListenUDPInit(void)
{
	CompatibleAddr ListenAddr;

	const char	*LocalAddr = ConfigGetString(&ConfigInfo, "LocalInterface");

	int			LocalPort = ConfigGetInt32(&ConfigInfo, "LocalPort");

	int			AddrLen;

	Family = GetAddressFamily(LocalAddr);

	ListenSocketUDP = socket(Family, SOCK_DGRAM, IPPROTO_UDP);

	if(ListenSocketUDP == INVALID_SOCKET)
	{
		int		ErrorNum = GET_LAST_ERROR();
		char	ErrorMessage[320];
		ErrorMessage[0] = '\0';

		GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));

		ERRORMSG("Creating UDP socket failed. %d : %s\n", ErrorNum, ErrorMessage);
		return -1;
	}

	memset(&ListenAddr, 0, sizeof(ListenAddr));

	if( Family == AF_INET )
	{
		FILL_ADDR4(ListenAddr.Addr4, AF_INET, LocalAddr, LocalPort);

		AddrLen = sizeof(struct sockaddr);
	} else {
		char Addr[LENGTH_OF_IPV6_ADDRESS_ASCII] = {0};

		sscanf(LocalAddr, "[%s]", Addr);

		ListenAddr.Addr6.sin6_family = Family;
		ListenAddr.Addr6.sin6_port = htons(LocalPort);
		IPv6AddressToNum(Addr, &(ListenAddr.Addr6.sin6_addr));

		AddrLen = sizeof(struct sockaddr_in6);
	}

	if(	bind(ListenSocketUDP, (struct sockaddr*)&(ListenAddr), AddrLen)
			!= 0
		)
	{
		int		ErrorNum = GET_LAST_ERROR();
		char	ErrorMessage[320];
		ErrorMessage[0] = '\0';

		GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));

		ERRORMSG("Opening UDP socket failed. %d : %s\n", ErrorNum, ErrorMessage);
		return -2;
	}

	CREATE_MUTEX(ListenMutex);
	CREATE_MUTEX(SendToMutex);

	MaximumMessageSize = GetMaximumMessageSize(ListenSocketUDP);
	if(MaximumMessageSize < 0)
	{
		MaximumMessageSize = 1000;
	}
	Inited = TRUE;

	return 0;
}

static int Query(	SOCKET				*PrimarySocket,
					SOCKET				*SecondarySocket,
					DNSQuaryProtocol	PrimaryProtocol,
					char				*QueryContent,
					int					QueryContentLength,
					CompatibleAddr		*ClientAddr,
					ExtendableBuffer	*Buffer
					)
{
	int					State;

	DNSRecordType		SourceType;

	char				ProtocolCharacter = ' ';

	char				QueryDomain[256];

	char				DateAndTime[32];

	QueryContext		Context;

	GetCurDateAndTime(DateAndTime, sizeof(DateAndTime));

	QueryDomain[0] = '\0';
	DNSGetHostName(QueryContent, DNSJumpHeader(QueryContent), QueryDomain);

	SourceType = (DNSRecordType)DNSGetRecordType(DNSJumpHeader(QueryContent));

	Context.PrimarySocket = PrimarySocket;
	Context.SecondarySocket = SecondarySocket;
	Context.PrimaryProtocolToServer = PrimaryProtocol;
	Context.ProtocolToSrc = DNS_QUARY_PROTOCOL_UDP;
	Context.Compress = TRUE;

	State = QueryBase(&Context,

					  QueryContent,
					  QueryContentLength,

					  Buffer,
					  QueryDomain,
					  SourceType,
					  &ProtocolCharacter
					  );

	switch( State )
	{
		case QUERY_RESULT_DISABLE:
			((DNSHeader *)(QueryContent)) -> Flags.Direction = 1;
			((DNSHeader *)(QueryContent)) -> Flags.ResponseCode = 5;
			if( Family == AF_INET )
			{
				_SendTo(ListenSocketUDP, QueryContent, QueryContentLength, 0, (struct sockaddr *)&(ClientAddr -> Addr4), sizeof(struct sockaddr));
				PRINT("%s[R][%s:%d][%s][%s] Refused.\n", DateAndTime, inet_ntoa(ClientAddr -> Addr4.sin_addr), ClientAddr -> Addr4.sin_port, DNSGetTypeName(SourceType), QueryDomain);
			} else {
				char Addr[LENGTH_OF_IPV6_ADDRESS_ASCII] = {0};

				IPv6AddressToAsc(&(ClientAddr -> Addr6.sin6_addr), Addr);

				_SendTo(ListenSocketUDP, QueryContent, QueryContentLength, 0, (struct sockaddr *)&(ClientAddr -> Addr6), sizeof(struct sockaddr_in6));
				PRINT("%s[R][%s:%d][%s][%s] Refused.\n", DateAndTime, Addr, ClientAddr -> Addr6.sin6_port, DNSGetTypeName(SourceType), QueryDomain);
			}
			return -1;
			break;

		case QUERY_RESULT_ERROR:
			if( ErrorMessages == TRUE )
			{
				int		ErrorNum = GET_LAST_ERROR();
				char	ErrorMessage[320];

				ErrorMessage[0] ='\0';

				GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));
				if( Family == AF_INET )
				{
					printf("%s[%c][%s][%s][%s] Error occured : %d : %s .\n",
						   DateAndTime,
						   ProtocolCharacter,
						   inet_ntoa(ClientAddr -> Addr4.sin_addr),
						   DNSGetTypeName(SourceType), QueryDomain,
						   ErrorNum,
						   ErrorMessage
						   );
				} else {
					char Addr[LENGTH_OF_IPV6_ADDRESS_ASCII] = {0};

					IPv6AddressToAsc(&(ClientAddr -> Addr6.sin6_addr), Addr);

					printf("%s[%c][%s][%s][%s] Error occured : %d : %s .\n",
						   DateAndTime,
						   ProtocolCharacter,
						   Addr,
						   DNSGetTypeName(SourceType), QueryDomain,
						   ErrorNum,
						   ErrorMessage
						   );
				}
			}
			return -1;
			break;

		default: /* Succeed */
			if(State > MaximumMessageSize)
			{
				State = MaximumMessageSize;
				((DNSHeader *)(QueryContent)) -> Flags.TrunCation = 1;
			}

			if( Family == AF_INET )
			{
				_SendTo(ListenSocketUDP, ExtendableBuffer_GetData(Buffer), State, 0, (struct sockaddr *)&(ClientAddr -> Addr4), sizeof(struct sockaddr));
			} else {
				_SendTo(ListenSocketUDP, ExtendableBuffer_GetData(Buffer), State, 0, (struct sockaddr *)&(ClientAddr -> Addr6), sizeof(struct sockaddr_in6));
			}

			if( ShowMassages == TRUE )
			{
				char InfoBuffer[3072];
				InfoBuffer[0] = '\0';
				GetAllAnswers(ExtendableBuffer_GetData(Buffer), InfoBuffer);

				if( Family == AF_INET )
				{
					PRINT("%s[%c][%s][%s][%s] :\n%s", DateAndTime, ProtocolCharacter, inet_ntoa(ClientAddr -> Addr4.sin_addr), DNSGetTypeName(SourceType), QueryDomain, InfoBuffer);
				} else {
					char Addr[LENGTH_OF_IPV6_ADDRESS_ASCII] = {0};

					IPv6AddressToAsc(&(ClientAddr -> Addr6.sin6_addr), Addr);

					PRINT("%s[%c][%s][%s][%s] :\n%s", DateAndTime, ProtocolCharacter, Addr, DNSGetTypeName(SourceType), QueryDomain, InfoBuffer);
				}
			}

			return 0;
	}
}

static int QueryDNSListenUDP(void *Unused){
	socklen_t			AddrLen;

	CompatibleAddr		ClientAddr;

	int					State;
	char				ResultBuffer[1024];
	ExtendableBuffer	Buffer;

	/* Sockets with server */
	SOCKET				TCPSocket			=	INVALID_SOCKET;
	SOCKET				UDPSocket			=	INVALID_SOCKET;
	SOCKET				*PrimarySocketPtr;
	SOCKET				*SecondarySocketPtr;
	DNSQuaryProtocol	PrimaryProtocol;

	char				ProtocolStr[8] = {0};

	/* Choose and fill Primary and Secondary */
	strncpy(ProtocolStr, ConfigGetString(&ConfigInfo, "PrimaryServer"), 3);
	StrToLower(ProtocolStr);

	if( strcmp(ProtocolStr, "tcp") == 0 )
	{
		PrimaryProtocol = DNS_QUARY_PROTOCOL_TCP;
		PrimarySocketPtr = &TCPSocket;

		if( ConfigGetString(&ConfigInfo, "UDPServer") != NULL )
			SecondarySocketPtr = &UDPSocket;
		else
			SecondarySocketPtr = NULL;

	} else {
		PrimaryProtocol = DNS_QUARY_PROTOCOL_UDP;
		PrimarySocketPtr = &UDPSocket;

		if( ConfigGetString(&ConfigInfo, "TCPServer") != NULL )
			SecondarySocketPtr = &TCPSocket;
		else
			SecondarySocketPtr = NULL;
	}

	ExtendableBuffer_Init(&Buffer, 512, 10240);

	++ThreadCount;
	while(TRUE)
	{
		memset(&ClientAddr, 0, sizeof(ClientAddr));
		GET_MUTEX(ListenMutex);

		if( Family == AF_INET )
		{
			AddrLen = sizeof(struct sockaddr);
			State = recvfrom(ListenSocketUDP, ResultBuffer, sizeof(ResultBuffer), 0, (struct sockaddr *)&(ClientAddr.Addr4), &AddrLen);

		} else {
			AddrLen = sizeof(struct sockaddr_in6);
			State = recvfrom(ListenSocketUDP, ResultBuffer, sizeof(ResultBuffer), 0, (struct sockaddr *)&(ClientAddr.Addr6), &AddrLen);

		}

		RELEASE_MUTEX(ListenMutex);

		if(State < 1)
		{
			if( ErrorMessages == TRUE )
			{
				int		ErrorNum = GET_LAST_ERROR();
				char	ErrorMessage[320];

				ErrorMessage[0] ='\0';

				GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));
				if( Family == AF_INET )
				{
					printf("An error occured while receiving from %s : %d : %s .\n",
						   inet_ntoa(ClientAddr.Addr4.sin_addr),
						   ErrorNum,
						   ErrorMessage
						   );
				} else {
					char Addr[LENGTH_OF_IPV6_ADDRESS_ASCII] = {0};

					IPv6AddressToAsc(&(ClientAddr.Addr6.sin6_addr), Addr);

					printf("An error occured while receiving from %s : %d : %s .\n",
						   Addr,
						   ErrorNum,
						   ErrorMessage
						   );

				}
			}
			continue;
		}

		Query(PrimarySocketPtr, SecondarySocketPtr, PrimaryProtocol, ResultBuffer, State, &ClientAddr, &Buffer);
		ExtendableBuffer_Reset(&Buffer);

	}
	--ThreadCount;
	return 0;
}

void QueryDNSListenUDPStart(int _ThreadCount)
{
	if(Inited == FALSE) return;
	if(_ThreadCount < 1) return;
	Threads = SafeMalloc(_ThreadCount * sizeof(ThreadHandle));
	ThreadCount = 0;
	for(; _ThreadCount != 0; --_ThreadCount)
	{
		CREATE_THREAD(QueryDNSListenUDP, NULL, Threads[_ThreadCount - 1]);
	}
	INFO("Starting UDP socket %s:%d successfully.\n", ConfigGetString(&ConfigInfo, "LocalInterface"),
													   ConfigGetInt32(&ConfigInfo, "LocalPort")
														);
}
