#include <stdio.h>
#include <ctype.h>
#include "addresslist.h"
#include "common.h"
#include "utils.h"

int AddressList_Init(AddressList *a)
{
	if( a == NULL )
	{
		return 0;
	}

	if( Array_Init(&(a ->AddressList), sizeof(struct _Address), 8, FALSE, NULL) != 0 )
	{
		return -1;
	}

	a -> Counter = 0;
	return 0;
}


int AddressList_Add(AddressList *a, sa_family_t family, void *Addr)
{
	struct _Address Address;

	if( a == NULL )
	{
		return 0;
	}

	switch( family )
	{
		case AF_INET:
			Address.family = family;
			memcpy(&(Address.Addr), Addr, sizeof(Address.Addr.Addr4));
			break;

		case AF_INET6:
			Address.family = family;
			memcpy(&(Address.Addr), Addr, sizeof(Address.Addr.Addr6));
			break;

		default:
			return 1;
			break;
	}

	return Array_PushBack(&(a -> AddressList), &Address, NULL);
}

int AddressList_Add_From_String(AddressList *a, const char *Addr_Port)
{
	struct	_Address	Tmp;
			sa_family_t	Family;

	memset(&Tmp, 0, sizeof(Tmp));

	Family = GetAddressFamily(Addr_Port);
	Tmp.family = Family;

	switch( Family )
	{
		case AF_INET6:
			{
				char		Addr[LENGTH_OF_IPV6_ADDRESS_ASCII] = {0};
				in_port_t	Port;
				const char	*PortPos;

				memset(Addr, 0, sizeof(Addr));

				PortPos = strchr(Addr_Port, ']');
				if( PortPos == NULL )
				{
					return -1;
				}

				PortPos = strchr(PortPos, ':');
				if( PortPos == NULL )
				{
					sscanf(Addr_Port, "[%s]", Addr);
					Port = 53;
				} else {
					int	Port_warpper;

					sscanf(Addr_Port + 1, "%[^]]", Addr);
					sscanf(PortPos + 1, "%d", &Port_warpper);
					Port = Port_warpper;
				}

				Tmp.Addr.Addr6.sin6_family = Family;
				Tmp.Addr.Addr6.sin6_port = htons(Port);

				IPv6AddressToNum(Addr, &(Tmp.Addr.Addr6.sin6_addr));

				return AddressList_Add(a, Family, &Tmp);
			}
			break;

		case AF_INET:
			{
				char		Addr[] = "xxx.xxx.xxx.xxx";
				in_port_t	Port;
				const char	*PortPos;

				memset(Addr, 0, sizeof(Addr));

				PortPos = strchr(Addr_Port, ':');
				if( PortPos == NULL )
				{
					sscanf(Addr_Port, "%s", Addr);
					Port = 53;
				} else {
					int Port_warpper;
					sscanf(Addr_Port, "%[^:]", Addr);
					sscanf(PortPos + 1, "%d", &Port_warpper);
					Port = Port_warpper;
				}
				FILL_ADDR4(Tmp.Addr.Addr4, Family, Addr, Port);

				return AddressList_Add(a, Family, &Tmp);
			}
			break;

		default:
			return -1;
			break;
	}

}

int AddressList_Incr(AddressList *a)
{
	if( a == NULL )
	{
		return 0;
	}

	return (a -> Counter)++;
}

struct sockaddr *AddressList_GetOne(AddressList *a, sa_family_t *family)
{
	struct _Address *Result;

	if( a == NULL || family == NULL )
	{
		return 0;
	}

	Result = (struct _Address *)Array_GetBySubscript(&(a -> AddressList), a -> Counter % Array_GetUsed(&(a -> AddressList)));
	if( Result == NULL )
	{
		return NULL;
	} else {
		*family = Result -> family;
		return (struct sockaddr *)&(Result -> Addr);
	}

}
