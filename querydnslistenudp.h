#ifndef _QUERY_DNS_UDP_H_
#define _QUERY_DNS_UDP_H_

#include "common.h"

int QueryDNSListenUDPInit(void);

void QueryDNSListenUDPStart(int ThreadCount);

#endif /* _QUERY_DNS_UDP_H_ */
