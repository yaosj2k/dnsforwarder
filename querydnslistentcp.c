#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "querydnslistentcp.h"
#include "querydnsbase.h"
#include "dnsrelated.h"
#include "dnsparser.h"
#include "dnsgenerator.h"
#include "common.h"
#include "utils.h"
#include "stringlist.h"
#include "excludedlist.h"
#include "addresslist.h"

/* Variables */
static BOOL			Inited = FALSE;

static SOCKET		ListenSocketTCP;

static sa_family_t	Family;

typedef struct _RecvInfo{
	SOCKET			Socket;
	CompatibleAddr	Peer;
}RecvInfo;

/* Functions */
int QueryDNSListenTCPInit(void)
{
	static struct _Address	ListenAddr;

	const char	*LocalAddr = ConfigGetString(&ConfigInfo, "LocalInterface");
	int			LocalPort = ConfigGetInt32(&ConfigInfo, "LocalPort");

	int			AddrLen;

	Family = GetAddressFamily(LocalAddr);

	ListenSocketTCP = socket(Family, SOCK_STREAM, IPPROTO_TCP);
	if(ListenSocketTCP == INVALID_SOCKET)
	{
		int		ErrorNum = GET_LAST_ERROR();
		char	ErrorMessage[320];
		ErrorMessage[0] = '\0';

		GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));

		ERRORMSG("Creating TCP socket failed. %d : %s\n", ErrorNum, ErrorMessage);
		return -1;
	}

	memset(&ListenAddr, 0, sizeof(ListenAddr));

	if( Family == AF_INET )
	{
		FILL_ADDR4(ListenAddr.Addr.Addr4, AF_INET, LocalAddr, LocalPort);

		AddrLen = sizeof(struct sockaddr);
	} else {
		char Addr[LENGTH_OF_IPV6_ADDRESS_ASCII] = {0};

		sscanf(LocalAddr, "[%s]", Addr);

		ListenAddr.Addr.Addr6.sin6_family = Family;
		ListenAddr.Addr.Addr6.sin6_port = htons(LocalPort);
		IPv6AddressToNum(Addr, &(ListenAddr.Addr.Addr6.sin6_addr));

		AddrLen = sizeof(struct sockaddr_in6);
	}

	if(	bind(ListenSocketTCP, (struct sockaddr*)&(ListenAddr.Addr), AddrLen) != 0 )
	{
		int		ErrorNum = GET_LAST_ERROR();
		char	ErrorMessage[320];
		ErrorMessage[0] = '\0';

		GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));

		ERRORMSG("Opening TCP socket failed. %d : %s\n", ErrorNum, ErrorMessage);
		return -2;
	}

	if( listen(ListenSocketTCP, 16) == SOCKET_ERROR )
	{
		int		ErrorNum = GET_LAST_ERROR();
		char	ErrorMessage[320];
		ErrorMessage[0] = '\0';

		GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));

		ERRORMSG("Opening TCP socket failed. %d : %s\n", ErrorNum, ErrorMessage);
		return -3;
	}

	Inited = TRUE;

	return 0;
}

static int Query(	SOCKET				*PrimarySocket,
					SOCKET				*SecondarySocket,
					DNSQuaryProtocol	PrimaryProtocol,
					char				*QueryContent,
					int					QueryContentLength,

					SOCKET				*ClientSocket,
					CompatibleAddr		*ClientAddr,
					ExtendableBuffer	*Buffer
					)
{
	int					State;

	DNSRecordType		SourceType;
	char				*DNSBody = DNSGetDNSBody(QueryContent);

	char				ProtocolCharacter = ' ';

	char				QueryDomain[256];

	char				DateAndTime[32];

	QueryContext		Context;

	GetCurDateAndTime(DateAndTime, sizeof(DateAndTime));

	QueryDomain[0] = '\0';
	DNSGetHostName(DNSBody, DNSJumpHeader(DNSBody), QueryDomain);

	SourceType = (DNSRecordType)DNSGetRecordType(DNSJumpHeader(DNSBody));

	Context.PrimarySocket = PrimarySocket;
	Context.SecondarySocket = SecondarySocket;
	Context.PrimaryProtocolToServer = PrimaryProtocol;
	Context.ProtocolToSrc = DNS_QUARY_PROTOCOL_TCP;
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
			((DNSHeader *)DNSBody) -> Flags.Direction = 1;
			((DNSHeader *)DNSBody) -> Flags.ResponseCode = 5;
			send(*ClientSocket, QueryContent, QueryContentLength, 0);
			if( Family == AF_INET )
			{
				PRINT("%s[R][%s:%d][%s][%s] Refused.\n", DateAndTime, inet_ntoa(ClientAddr -> Addr4.sin_addr), ClientAddr -> Addr4.sin_port, DNSGetTypeName(SourceType), QueryDomain);
			} else {
				char Addr[LENGTH_OF_IPV6_ADDRESS_ASCII] = {0};

				IPv6AddressToAsc(&(ClientAddr -> Addr6.sin6_addr), Addr);

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
						   DNSGetTypeName(SourceType),
						   QueryDomain,
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
						   DNSGetTypeName(SourceType),
						   QueryDomain,
						   ErrorNum,
						   ErrorMessage
						   );
				}
			}
			return -1;
			break;

		default: /* Succeed */
			send(*ClientSocket, ExtendableBuffer_GetData(Buffer), State, 0);

			if( ShowMassages == TRUE )
			{
				char InfoBuffer[3072];
				InfoBuffer[0] = '\0';
				GetAllAnswers(DNSGetDNSBody(ExtendableBuffer_GetData(Buffer)), InfoBuffer);

				if( Family == AF_INET )
				{
					PRINT("%s[%c][%s][%s][%s] :\n%s", DateAndTime, ProtocolCharacter, inet_ntoa(ClientAddr ->Addr4.sin_addr), DNSGetTypeName(SourceType), QueryDomain, InfoBuffer);
				} else {
					char Addr[LENGTH_OF_IPV6_ADDRESS_ASCII] = {0};

					IPv6AddressToAsc(&(ClientAddr -> Addr6.sin6_addr), Addr);

					PRINT("%s[%c][%s][%s][%s] :\n%s", DateAndTime, ProtocolCharacter, Addr, DNSGetTypeName(SourceType), QueryDomain, InfoBuffer);
				}
			}
			return 0;
			break;

	}
}

static int TCPRecv(RecvInfo *Info)
{
	SOCKET				Socket	=	Info -> Socket;
	CompatibleAddr		Peer	=	Info -> Peer;
	int					state;
	char				ResultBuffer[1024];
	ExtendableBuffer	Buffer;

	/* Sockets to server */
	SOCKET				TCPSocket = INVALID_SOCKET;
	SOCKET				UDPSocket = INVALID_SOCKET;
	SOCKET				*PrimarySocketPtr;
	SOCKET				*SecondarySocketPtr;
	DNSQuaryProtocol	PrimaryProtocol;

	char				ProtocolStr[8] = {0};

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

	while(TRUE){
		state = recv(Socket, ResultBuffer, sizeof(ResultBuffer), MSG_NOSIGNAL);
		if(GET_LAST_ERROR() == TCP_TIME_OUT)
		{
			break;
		}

		if( state < 1 )
		{
			break;
		}

		Query(PrimarySocketPtr, SecondarySocketPtr, PrimaryProtocol, ResultBuffer, state, &Socket, &Peer, &Buffer);
		ExtendableBuffer_Reset(&Buffer);

	}

	CLOSE_SOCKET(TCPSocket);
	CLOSE_SOCKET(UDPSocket);

	CLOSE_SOCKET(Socket);

	if( Family == AF_INET )
	{
		INFO("Closed TCP connection to %s:%d\n", inet_ntoa(Peer.Addr4.sin_addr), Peer.Addr4.sin_port);
	} else {
		char Addr[LENGTH_OF_IPV6_ADDRESS_ASCII] = {0};

		IPv6AddressToAsc(&(Peer.Addr6.sin6_addr), Addr);

		INFO("Closed TCP connection to %s:%d\n", Addr, Peer.Addr6.sin6_port);
	}

	SafeFree(Info);

	EXIT_THREAD(0);
}

static int QueryDNSListenTCP(void *Unused)
{
	static ThreadHandle	Unused2;
	RecvInfo			*Info = NULL;
	CompatibleAddr		*Peer;
	socklen_t			AddrLen;

	while(TRUE){

		Info = SafeMalloc(sizeof(RecvInfo));

		Peer = &(Info -> Peer);
		memset(Info, 0, sizeof(CompatibleAddr));

		if( Family == AF_INET )
		{
			AddrLen = sizeof(struct sockaddr);
			Info -> Socket = accept(ListenSocketTCP, (struct sockaddr *)&(Peer -> Addr4), (socklen_t *)&AddrLen);
		} else {
			AddrLen = sizeof(struct sockaddr_in6);
			Info -> Socket = accept(ListenSocketTCP, (struct sockaddr *)&(Peer -> Addr6), (socklen_t *)&AddrLen);
		}

		if(Info -> Socket == INVALID_SOCKET)
		{
			SafeFree(Info);
			continue;
		}

		SetSocketWait(Info -> Socket, TRUE);
		SetSocketRecvTimeLimit(Info -> Socket, 2000);

		if( Family == AF_INET )
		{
			INFO("Established TCP connection to %s:%d\n", inet_ntoa(Peer -> Addr4.sin_addr), Peer -> Addr4.sin_port);
		} else {
			char Addr[LENGTH_OF_IPV6_ADDRESS_ASCII] = {0};

			IPv6AddressToAsc(&(Peer -> Addr6.sin6_addr), Addr);

			INFO("Established TCP connection to %s:%d\n", Addr, Peer -> Addr6.sin6_port);
		}

		CREATE_THREAD(TCPRecv, (void *)Info, Unused2);
#ifdef WIN32
		CloseHandle(Unused2);
#endif /* WIN32 */
	}
	CLOSE_SOCKET(ListenSocketTCP);
	return 0;
}

void QueryDNSListenTCPStart(void)
{
	static ThreadHandle	Unused;

	if(Inited == FALSE)
		return;

	INFO("Starting TCP socket %s:%d successfully.\n", ConfigGetString(&ConfigInfo, "LocalInterface"),
													   ConfigGetInt32(&ConfigInfo, "LocalPort")
													   );
	CREATE_THREAD(QueryDNSListenTCP, NULL, Unused);
#ifdef WIN32
	CloseHandle(Unused);
#endif /* WIN32 */
}
