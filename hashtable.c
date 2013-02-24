#include <string.h>
#include "hashtable.h"
#include "common.h"
#include "utils.h"

int HashTable_CalculateAppropriateSlotCount(int ElementCount)
{
	if( ElementCount > 10 )
	{
		ElementCount /= 3;
		return ROUND(ElementCount, 10) + 6;
	} else {
		return 3;
	}
}

static int ELFHash(char *str)
{
	_32BIT_UINT h = 0;
	_32BIT_UINT x = 0;

	while( *str != '\0' )
	{
		h += *str;
		h <<= 4;

		x = h & 0xF0000000;
		if( x != 0 )
		{
			h ^= (x >> 24);

		}
		h &= ~x;
		str++;
	}
	return (h & 0x7FFFFFFF);
}

int HashTable_Init(HashTable *h, int DataLength, int InitialCount)
{
	int	loop;
	int	SlotCount;
	if( h == NULL)
		return -1;

	SlotCount = HashTable_CalculateAppropriateSlotCount(InitialCount);

	if( Array_Init(&(h -> NodeChunk), DataLength + sizeof(NodeHead), InitialCount, FALSE, NULL) != 0 )
		return 1;

	if( Array_Init(&(h -> Slots), sizeof(NodeHead), SlotCount, FALSE, NULL) != 0 )
		return 2;

	h -> Slots.Used = h -> Slots.Allocated;

	for(loop = 0; loop != h -> Slots.Allocated; ++loop)
	{
		((NodeHead *)Array_GetBySubscript(&(h -> Slots), loop)) -> Next = HASHTABLE_NODE_END;
	}

	h -> RemovedNodes = -1;

	return 0;
}

int HashTable_Init_Manually(HashTable	*h,
							void		*SlotsStartAddress,
							_32BIT_INT	SlotsCount,
							void		*NodeChunkStartAddress,
							BOOL		GrowDown,
							_32BIT_INT	DataLength
							)
{
	h -> Slots.Used = SlotsCount;
	h -> Slots.DataLength = sizeof(NodeHead);
	h -> Slots.Data = SlotsStartAddress;
	h -> Slots.Allocated = SlotsCount;

	h -> NodeChunk.DataLength = DataLength;
	h -> NodeChunk.Data = NodeChunkStartAddress;
	h -> NodeChunk.Used = 0;

	if( GrowDown == TRUE )
	{
		h -> NodeChunk.Allocated = -1;
	} else {
		h -> NodeChunk.Allocated = 0;
	}

	h -> RemovedNodes = -1;

	return 0;
}

int HashTable_CreateNewNode(HashTable *h, NodeHead **Out, void *Boundary /* Only used by grow down array */)
{
	int			NewNode_i;
	NodeHead	*NewNode;

	Array		*NodeChunk;

	NodeChunk = &(h -> NodeChunk);

	NewNode_i = Array_PushBack(NodeChunk, NULL, Boundary);
	if( NewNode_i < 0 )
	{
		return -1;
	}

	NewNode = (NodeHead *)Array_GetBySubscript(NodeChunk, NewNode_i);
	NewNode -> Next = HASHTABLE_NODE_NEWLY_CREATED;

	if( Out != NULL )
	{
		*Out = NewNode;
	}

	return NewNode_i;
}



_32BIT_INT HashTable_FindUnusedNode(HashTable *h,
									NodeHead **Out,
									_32BIT_INT Start /* Initially -1 */,
									void *Boundary /* Only used by grow down array */,
									BOOL AutoCreateNewNode
									)
{
	_32BIT_INT	Subscript;
	NodeHead	*Node;

	Array		*NodeChunk;

	NodeChunk = &(h -> NodeChunk);

	if( Start == HASHTABLE_FINDUNUSEDNODE_START )
	{
		Subscript = h -> RemovedNodes;
	} else if( Start >= 0 ){
		Node = (NodeHead *)Array_GetBySubscript(NodeChunk, Start);
		Subscript = Node -> Next;
	} else {
		if( Out != NULL )
		{
			*Out = NULL;
		}
		return HASHTABLE_FINDUNUSEDNODE_FAILED;
	}

	if( Subscript >= 0 )
	{
		Node = (NodeHead *)Array_GetBySubscript(NodeChunk, Subscript);

		if( Out != NULL )
		{
			*Out = Node;
		}

		return Subscript;
	}

	if( AutoCreateNewNode == TRUE )
	{
		return HashTable_CreateNewNode(h, Out, Boundary);
	} else {
		if( Out != NULL )
		{
			*Out = NULL;
		}
		return HASHTABLE_FINDUNUSEDNODE_FAILED;
	}
}

_32BIT_INT HashTable_FetchNode(HashTable *h, NodeHead *Node)
{
	_32BIT_INT	NextNode;
	Array		*NodeChunk;

	if( Node -> Next == HASHTABLE_NODE_NEWLY_CREATED )
	{
		return -1;
	}

	NodeChunk = &(h -> NodeChunk);

	if( Node -> Prev >= 0 )
	{
		NodeHead	*NextRemovedNode;
		NextRemovedNode = (NodeHead *)Array_GetBySubscript(NodeChunk, Node -> Prev);
		NextRemovedNode -> Next = Node -> Next;
	} else {
		h -> RemovedNodes = Node -> Next;
	}

	if( Node -> Next >= 0 )
	{
		NodeHead	*PreviousRemovedNode;
		PreviousRemovedNode = (NodeHead *)Array_GetBySubscript(NodeChunk, Node -> Next);
		PreviousRemovedNode -> Prev = Node -> Prev;
	}

	NextNode = Node -> Next;

	Node -> Next = HASHTABLE_NODE_UNUSED;
	Node -> Prev = HASHTABLE_NODE_UNUSED;

	return NextNode;
}

int HashTable_AddByNode(HashTable *h, char *Key, int Node_index, NodeHead *Node)
{
	int			Slot_i;
	NodeHead	*Slot;

	if( h == NULL || Key == NULL || Node_index < 0 || Node == NULL )
		return -1;

	Slot_i = ELFHash(Key) % (h -> Slots.Allocated - 1);
	Slot = (NodeHead *)Array_GetBySubscript(&(h -> Slots), Slot_i);
	if( Slot == NULL )
		return -2;

	if( Slot -> Next >= 0 )
	{
		((NodeHead *)Array_GetBySubscript(&(h -> NodeChunk), Slot -> Next)) -> Prev = Node_index;
	}

	Node -> Next = Slot -> Next;
	Node -> Prev = (-1) * (Slot_i + 1);
	Slot -> Next = Node_index;

	return 0;
}

int HashTable_Add(HashTable *h, char *Key, void *Data)
{
	_32BIT_INT	Slot_i;
	NodeHead	*Slot;
	_32BIT_INT	NewNode_i;
	NodeHead	*NewNode = NULL;

	Slot_i = ELFHash(Key) % (h -> Slots.Allocated - 1);
	Slot = (NodeHead *)Array_GetBySubscript(&(h -> Slots), Slot_i);
	if( Slot == NULL )
		return -2;

	NewNode_i = HashTable_FindUnusedNode(h, &NewNode, -1, NULL, TRUE);

	if( NewNode_i < 0 )
		return -3;

	HashTable_FetchNode(h, NewNode);

	memcpy(NewNode + 1, Data, h -> NodeChunk.DataLength - sizeof(NodeHead));

	return HashTable_AddByNode(h, Key, NewNode_i, NewNode);
}

void HashTable_RemoveNode(HashTable *h, _32BIT_INT SubScriptOfNode, NodeHead *Node)
{
	Array	*NodeChunk;

	NodeChunk = &(h -> NodeChunk);

	if( SubScriptOfNode < 0 )
	{
		SubScriptOfNode = ((char *)Node - (char *)(NodeChunk -> Data)) / (NodeChunk -> DataLength);
		if( NodeChunk -> Allocated < 0 )
		{
			SubScriptOfNode *= (-1);
		}
	}

	if( Node == NULL )
	{
		Node = (NodeHead *)Array_GetBySubscript(&(h -> NodeChunk), SubScriptOfNode);
	}

	if( Node -> Next != HASHTABLE_NODE_UNUSED )
	{
		if( Node -> Next >= 0 )
		{
			((NodeHead *)Array_GetBySubscript(NodeChunk, Node -> Next)) -> Prev = Node -> Prev;
		}

		if( Node -> Prev < 0 )
		{
			/* If prev is a slot */
			((NodeHead *)Array_GetBySubscript(&(h -> Slots), (-1) * (Node -> Prev) - 1)) -> Next = Node -> Next;
		} else {
			/* If prev is a node. */
			((NodeHead *)Array_GetBySubscript(NodeChunk, Node -> Prev)) -> Next = Node -> Next;
		}

		if( SubScriptOfNode != NodeChunk -> Used - 1 )
		{

			if( h -> RemovedNodes >= 0 )
			{
				NodeHead	*PreviousRemovedNode;
				PreviousRemovedNode = (NodeHead *)Array_GetBySubscript(NodeChunk, h -> RemovedNodes);
				PreviousRemovedNode -> Prev = SubScriptOfNode;
			}

			Node -> Next = h -> RemovedNodes;
			Node -> Prev = -1;
			h -> RemovedNodes = SubScriptOfNode;
		} else {
			--(NodeChunk -> Used);
		}
	} else {
		if( SubScriptOfNode == NodeChunk -> Used - 1 )
		{
			--(NodeChunk -> Used);
		}
	}

}

void *HashTable_Get(HashTable *h, char *Key, void *Start)
{
	int			Slot_i;
	NodeHead	*Head;

	if( h == NULL || Key == NULL)
		return NULL;

	if( Start == NULL )
	{
		Slot_i = ELFHash(Key) % (h -> Slots.Allocated - 1);
		Head = (NodeHead *)Array_GetBySubscript(&(h -> Slots), Slot_i);

		Head = (NodeHead *)Array_GetBySubscript(&(h -> NodeChunk), Head -> Next);
		if( Head == NULL )
			return NULL;

		return (void *)(Head + 1);

	} else {
		Head = (NodeHead *)Start - 1;

		Head = (NodeHead *)Array_GetBySubscript(&(h -> NodeChunk), Head -> Next);
		if( Head == NULL )
			return NULL;

		return (void *)(Head + 1);
	}

}

void HashTable_Free(HashTable *h)
{
	Array_Free(&(h -> NodeChunk));
	Array_Free(&(h -> Slots));
	h -> RemovedNodes = -1;
}
