#ifndef HOSTS_H_INCLUDED
#define HOSTS_H_INCLUDED

#include "querydnsbase.h"
#include "extendablebuffer.h"

#define DOMAIN_NAME_LENGTH_MAX 128

typedef struct _Host4{
	_32BIT_INT	Domain; /* Offset */
	char	IP[sizeof(struct in_addr)];
}Host4;

typedef struct _Host6{
	_32BIT_INT	Domain; /* Offset */
	char	IP[16];
}Host6;

typedef struct _HostCName{
	_32BIT_INT	Domain; /* Offset */
	_32BIT_INT	CName;
}HostCName;

typedef struct _HostDisabled{
	_32BIT_INT	Domain; /* Offset */
}HostDisabled;

int Hosts_Init(void);

BOOL Hosts_IsInited(void);

int Hosts_GetByQuestion(char *Question, ExtendableBuffer *Buffer, int *AnswerCount, QueryContext *Context);

#endif // HOSTS_H_INCLUDED
