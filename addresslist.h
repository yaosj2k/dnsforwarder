/* Address List
 *
 */



#ifndef ADDRESSLIST_H_INCLUDED
#define ADDRESSLIST_H_INCLUDED

#include "array.h"
#include "common.h"


struct _Address{

	/* Union of address of IPv4 and IPv6 */
	union {
		struct sockaddr_in	Addr4;
		struct sockaddr_in6	Addr6;
	}		Addr;

	/* Although there is a `family' field in both `struct sockaddr_in' and
	 * `struct sockaddr_in6', we also add it out here.
	 */
	sa_family_t	family;

};

typedef struct _AddressList {

	/* An array of `struct _Address' */
	Array		AddressList;

	/* The `Counter' is used by `AddressList_Incr' and `AddressList_GetOne',
	 * see them.
	 */
	_32BIT_UINT	Counter;
} AddressList;


int AddressList_Init(__in AddressList *a);
/* Description:
 *  Initialize an AddressList.
 * Parameters:
 *  a : The AddressList to be initialized.
 * Return value:
 *  0 on success, a non-zero value otherwise.
 */

int AddressList_Add(__in	AddressList	*a,
					__in	sa_family_t	family,
					__in	void		*Addr);
/* Description:
 *  Add an address in the form of `struct sockaddr_in' or `struct sockaddr_in6'
 *  to an AddressList.
 * Parameters:
 *  a      : The AddressList to be added in.
 *  family : Family of the address to be added.
 *  Addr   : The added adress, which is a pointer to a `struct sockaddr_in'
 *           or `struct sockaddr_in6'.
 * Return value:
 *  0 on success, a non-zero value otherwise.
 */

int AddressList_Add_From_String(__in	AddressList	*a,
								__in	const char		*Addr_Port);
/* Description:
 *  Add an address in text to an AddressList.
 * Parameters:
 *  a         : The AddressList to be added in.
 *  Addr_Port : A string in the form of IP:Port, which will be interpreted
 *              to a typical address struct and added to the AddressList.
 *                `Port' and the colon just before it can be omitted,
 *              in this case, the port will be assumed to be 53.
 *                An IPv6 IP should be enclosed in square bracket,
 *              like [2001:a5::1], in order not to be confused with :Port.
 *              The full IPv6:Port is like [2001:a5::1]:80 .
 * Return value:
 *  0 on success, a non-zero value otherwise.
 */

int AddressList_Incr(__in AddressList *a);
/* Description:
 *  Increase a -> Counter by 1 .
 * Return value:
 *  The a -> Counter before it increased.
 */

struct sockaddr *AddressList_GetOne(__in		AddressList	*a,
									__out_opt	sa_family_t	*family);
/* Description:
 *  Fetch an address from an AddressList. See the implementation for details.
 * Parameters:
 *  a      : The AddressList fetched from.
 *  family : A pointer to a `sa_family_t' which will be assigned to the family
 *           of the returned the address. This parameter can be NULL.
 * Return value:
 *  The pointer to the fetched address.
 */

#define AddressList_Free(a_ptr)	(Array_Free(&((a_ptr) -> AddressList)))
/* Description:
 *  Free an initialized AddressList.
 * Return value:
 *  Apparently.
 */

#endif // ADDRESSLIST_H_INCLUDED
