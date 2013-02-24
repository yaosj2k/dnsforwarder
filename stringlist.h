#ifndef STRINGLIST_H_INCLUDED
#define STRINGLIST_H_INCLUDED

#include "common.h"
#include "extendablebuffer.h"

typedef ExtendableBuffer StringList;

int StringList_Init(__in StringList *s, __in const char *ori, __in char Delimiter);

const char *StringList_GetNext(__in StringList *s, __in const char *Current);

const char *StringList_Get(__in StringList *s, __in int Subscript);

int StringList_Count(StringList *s);

_32BIT_INT StringList_Add(StringList *s, const char *str);

#define	StringList_GetByOffset(s_ptr, offset)	((const char *)((s_ptr) -> Data + (offset)))

#define StringList_Clear(s_ptr)	((s_ptr) -> Used = 0, (s_ptr) -> Data != NULL && *((s_ptr) -> Data) = '\0')

const char *StringList_Find(StringList *s, const char *str);

#define StringList_Free(s_ptr)	(ExtendableBuffer_Free((ExtendableBuffer *)(s_ptr)))

#endif // STRINGLIST_H_INCLUDED
