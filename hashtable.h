#ifndef HASHTABLE_H_INCLUDED
#define HASHTABLE_H_INCLUDED

#include "array.h"

#define	HASHTABLE_NODE_END				(-1)
#define	HASHTABLE_NODE_UNUSED			(-2)
#define	HASHTABLE_NODE_UNAVAILABLE		(-3)
#define	HASHTABLE_NODE_NEWLY_CREATED	(-4)

typedef struct _NodeHead{
	_32BIT_INT	Next; /* This value can be HASHTABLE_NODE_END if this node is a end, HASHTABLE_NODE_UNUSED if this node has been removed, or a non-negative number otherwise. */
	_32BIT_INT	Prev; /* If this value is negative, it denote the subscript of Slots, Prev == (-1) * (Subscript + 1). A non-negative number otherwise. */
}NodeHead;

typedef struct _HashTable{
	Array		NodeChunk;
	Array		Slots;
	_32BIT_INT	RemovedNodes;
}HashTable;

int HashTable_Init(HashTable *h, int DataLength, int InitialCount);

int HashTable_Init_Manually(HashTable	*h,
							void		*SlotsStartAddress,
							_32BIT_INT	SlotsCount,
							void		*NodeChunkStartAddress,
							BOOL		GrowDown,
							_32BIT_INT	DataLength
							);

#define HashTable_SetSlotsStartAddress(h_ptr, addr)	((h_ptr) -> Slots.Data = (addr))

#define HashTable_SetNodeChunkStartAddress(h_ptr, addr)	((h_ptr) -> NodeChunk.Data = (addr))

int HashTable_CalculateAppropriateSlotCount(int ElementCount);

int HashTable_CreateNewNode(HashTable *h, NodeHead **Out, void *Boundary /* Only used by grow down array */);

#define HASHTABLE_FINDUNUSEDNODE_START	(-1)
#define HASHTABLE_FINDUNUSEDNODE_FAILED	(-2)
_32BIT_INT HashTable_FindUnusedNode(HashTable *h, NodeHead **Out, _32BIT_INT Start, void *Boundary, BOOL AutoCreateNewNode);

_32BIT_INT HashTable_FetchNode(HashTable *h, NodeHead *Node);

int HashTable_AddByNode(HashTable *h, char *Key, int Node_index, NodeHead *Node);

int HashTable_Add(HashTable *h, char *Key, void *Data);

#define	HashTable_GetDataByNode(Node_ptr)	((void *)((NodeHead *)(Node_ptr) + 1))

#define	HashTable_GetNodeBySubscript(h_ptr, Subscript)	((NodeHead *)Array_GetBySubscript(&((h_ptr) -> NodeChunk), (Subscript)))

void *HashTable_Get(HashTable *h, char *Key, void *Start);

void HashTable_RemoveNode(HashTable *h, _32BIT_INT SubScriptOfNode, NodeHead *Node);

void HashTable_Free(HashTable *h);

#endif // HASHTABLE_H_INCLUDED
