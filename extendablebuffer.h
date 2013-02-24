#ifndef EXTENDABLEBUFFER_H_INCLUDED
#define EXTENDABLEBUFFER_H_INCLUDED

#include "common.h"

typedef struct _ExtendableBuffer{

	/* All datas reside here. */
	volatile char	*Data;

	/* How many bytes have been used. */
	_32BIT_UINT		Used;

	/* How many bytes have allocated. */
	_32BIT_UINT		Allocated;

	/* Length of bytes allocated when initializing */
	_32BIT_UINT		InitialSize;

	/* GuardSize */
	_32BIT_INT		GuardSize;
} ExtendableBuffer;

int ExtendableBuffer_Init(	__in ExtendableBuffer	*eb,
							__in _32BIT_UINT		InitSize,
							__in _32BIT_INT			GuardSize);
/* Description:
 *  Initialize an ExtendableBuffer.
 * Parameters:
 *  eb        : The ExtendableBuffer to be initialized.
 *  InitSize  : The initial buffer size.
 *  GuardSize : Set `GuardSize'. This parameter can be negative if it doesn't
 *              need a guard.
 * Return value:
 *  0 on success, a non-zero value otherwise.
 */

#define ExtendableBuffer_GetData(eb_ptr)	((char *)((eb_ptr) -> Data))
/* Description:
 *  Get the whole data of an ExtendableBuffer.
 * Parameters:
 *  eb_ptr : The ExtendableBuffer to be gotten from.
 * Return value:
 *  The data being gotten.
 */

#define ExtendableBuffer_GetUsedBytes(eb_ptr)	((eb_ptr) -> Used)
/* Description:
 *  Decide how many bytes have been used.
 * Parameters:
 *  eb_ptr : The ExtendableBuffer to be decided.
 * Return value:
 *  The number of used bytes.
 */

BOOL ExtendableBuffer_GuarantyLeft(	__in ExtendableBuffer	*eb,
									__in _32BIT_UINT		GuarantiedSize);
/* Description:
 *  Make sure that the number of unused(left) bytes (`Allocated' - `Used') is
 *  greater than `GuarantiedSize'. Straightforwardly, make sure the unused
 *  allocated space enough. This function will do realloc if necessary.
 *    There are 4 cases:
 *  Case 1 : Left bytes are enough : `Allocated' - `Used' >= `GuarantiedSize' :
 *    Simply return TRUE.
 *  Case 2 : Left bytes are not enough and all allocated bytes haven't exceed
 *  the `GuardSize' : `Allocated' - `Used' < `GuarantiedSize' and
 *  `GuardSize' >= 0 and `Allocated' <= `GuardSize' :
 *    Do realloc to make sure `Allocated' - `Used' >= `GuarantiedSize', if it
 *  success, returns TRUE, or FALSE otherwise.
 *  Case 3 : Left bytes are not enough but all allocated bytes have exceed the
 *  `GuardSize' : `Allocated' - `Used' < `GuarantiedSize' and `GuardSize' >= 0
 *  and `Allocated' > `GuardSize' :
 *    Simply return FALSE.
 *  Case 4 : Left bytes are not enough and there is no guard :
 *  `Allocated' - `Used' < `GuarantiedSize' and `GuardSize' < 0 :
 *    The same as case 2.
 * Parameters:
 *  eb             : The ExtendableBuffer to be guarantied.
 *  GuarantiedSize : The guarantied size.
 * Return value:
 *  TRUE if it can be guarantied. Or FALSE otherwise.
 */

char *ExtendableBuffer_Expand(	__in ExtendableBuffer	*eb,
								__in _32BIT_UINT		ExpandedSize);
/* Description:
 *  Increase the number of used bytes by `ExpandedSize'. There is a call to
 *  `ExtendableBuffer_GuarantyLeft' in this function, to make sure there is
 *  enough legal space to expand.
 * Parameters:
 *  eb           : The ExtendableBuffer to expand.
 *  ExpandedSize : Expanded size.
 * Return value:
 *  The head address of the newly expanded space.
 */

#define	ExtendableBuffer_GetEndOffset(eb_ptr)	((eb_ptr) -> Used)
/* Description:
 *  Decide the offset (in bytes) of the byte just after the last used byte. We
 *  call this offset end offset.
 *    The 'offset' here means the distance between `Data' and the byte, and
 *  a 'used byte' is such a byte that has an offset less than `Used'.
 * Parameters:
 *  eb_ptr : The ExtendableBuffer to be decided.
 * Return value:
 *  End offset.
 */

#define	ExtendableBuffer_SetEndOffset(eb_ptr, val)	((eb_ptr) -> Used = (val))

#define	ExtendableBuffer_GetPositionByOffset(eb_ptr, offset)	(((eb_ptr) -> Data + (offset)))

_32BIT_INT ExtendableBuffer_Add(ExtendableBuffer *eb, const char *Data, _32BIT_UINT DataLength);

char *ExtendableBuffer_Eliminate(ExtendableBuffer *eb, _32BIT_UINT Start, _32BIT_UINT Length);

#define	ExtendableBuffer_Eliminate_Tail(eb_ptr, length)	(((eb_ptr) -> Used) -= (length))

void ExtendableBuffer_Reset(ExtendableBuffer *eb);

void ExtendableBuffer_Free(ExtendableBuffer *eb);

#endif // EXTENDABLEBUFFER_H_INCLUDED
