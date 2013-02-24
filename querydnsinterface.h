#ifndef QUERYDNS_INTERFACE_INCLUDED
#define QUERYDNS_INTERFACE_INCLUDED

#include "common.h"

int QueryDNSInterfaceInit(char *ConfigFile, BOOL _ShowMassages, BOOL OnlyErrorMessages);

int QueryDNSInterfaceStart(void);

void QueryDNSInterfaceWait(void);

#endif // QUERYDNS_INTERFACE_INCLUDED
