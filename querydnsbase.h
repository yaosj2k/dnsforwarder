#ifndef _QUERY_DNS_BASE_H_
#define _QUERY_DNS_BASE_H_

#include "common.h"
#include "dnscache.h"
#include "readconfig.h"
#include "extendablebuffer.h"

#define	PRINT(...)		if(ShowMassages == TRUE) printf(__VA_ARGS__);
#define	INFO(...)		if(ShowMassages == TRUE) printf("[INFO] "__VA_ARGS__);
#define	ERRORMSG(...)	if(ErrorMessages == TRUE) fprintf(stderr, "[ERROR] "__VA_ARGS__);
#define	DEBUG(...)		if(Debug == TRUE) fprintf(stderr, "[DEBUG] "__VA_ARGS__);

extern ConfigFileInfo	ConfigInfo;
extern int				TimeToServer;
extern BOOL				ShowMassages;
extern BOOL				ErrorMessages;
extern BOOL				Debug;

typedef enum _dns_quary_protocol{
	DNS_QUARY_PROTOCOL_UDP = 0,
	DNS_QUARY_PROTOCOL_TCP = 1
}DNSQuaryProtocol;

typedef struct _QueryContext{
	SOCKET	*PrimarySocket;
	SOCKET	*SecondarySocket;

	DNSQuaryProtocol	PrimaryProtocolToServer;
	DNSQuaryProtocol	ProtocolToSrc;

	BOOL	Compress;
} QueryContext;

int DNSQueryFromCache(	__in	QueryContext		*Context,
						__in	char				*QueryingBody,
						__in	int					QueryingLength,
						__out	ExtendableBuffer	*Buffer
						);

int DNSQueryOriginViaTCP(SOCKET				Sock,
						const void			*OriginDNSBody,
						int					OriginDNSBodyLength,
						DNSQuaryProtocol	OriginProtocol,
						ExtendableBuffer	*ResultBuffer
					  );

int DNSQueryOriginViaUDP(SOCKET				Sock,
						struct sockaddr		*PeerAddr,
						sa_family_t			Family,
						const void			*OriginDNSBody,
						int					OriginDNSBodyLength,
						DNSQuaryProtocol	OriginProtocol,
						ExtendableBuffer	*ResultBuffer
					  );

int InitAddress(void);

int QueryFromHostsAndCache(QueryContext		*Context,
						   char				*QueryContent,
						   int				QueryContentLength,
						   ExtendableBuffer	*Buffer,
						   char				*ProtocolCharacter
						  );

int QueryFromServer(SOCKET				*Socket,
					struct	sockaddr	*PeerAddr,
					sa_family_t			Family,
					DNSQuaryProtocol	ProtocolToServer,
					char				*QueryContent,
					int					QueryContentLength,
					DNSQuaryProtocol	ProtocolToSrc,
					ExtendableBuffer	*Buffer
					);

#define QUERY_RESULT_DISABLE	(-1)
#define QUERY_RESULT_ERROR		(-2)

int QueryBase(QueryContext		*Context,
			  char				*QueryContent,
			  int				QueryContentLength,
			  ExtendableBuffer	*Buffer,
			  const char		*QueryDomain,
			  DNSRecordType		SourceType,
			  char				*ProtocolCharacter
			  );

int	GetAnswersByName(QueryContext *Context, const char *Name, DNSRecordType Type, ExtendableBuffer	*Buffer);

int SetSocketWait(SOCKET sock, BOOL Wait);

int SetSocketSendTimeLimit(SOCKET sock, int time);

int SetSocketRecvTimeLimit(SOCKET sock, int time);

int GetMaximumMessageSize(SOCKET sock);

void CloseTCPConnection(SOCKET *sock);

BOOL SocketIsStillReadable(SOCKET Sock);

BOOL TCPSocketIsHealthy(SOCKET *sock);

BOOL ConnectToTCPServer(SOCKET *sock, struct sockaddr *addr, sa_family_t Family, int TimeToServer);

#endif /* _QUERY_DNS_BASE_H_ */
