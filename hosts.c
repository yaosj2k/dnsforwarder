#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include "hosts.h"
#include "hashtable.h"
#include "dnsrelated.h"
#include "dnsgenerator.h"
#include "common.h"
#include "utils.h"
#include "downloader.h"
#include "readline.h"
#include "stringlist.h"
#include "querydnsbase.h"
#include "rwlock.h"

static BOOL			Inited = FALSE;

static BOOL			Internet = FALSE;

static int			FlushTime;

static time_t		LastFlush = 0;

static const char 	*File = NULL;

static ThreadHandle	GetHosts_Thread;

static RWLock		HostsLock;

static HashTable	A;
static HashTable	AAAA;
static HashTable	CName;
static HashTable	Disabled;
static Array		AW;
static Array		AAAAW;
static Array		CNameW;
static Array		DisabledW;

static StringList	StringChunk;

static StringList	AppendedHosts;
static int			AppendedNum = 0;

typedef enum _HostsRecordType{
	HOSTS_TYPE_UNKNOWN = 0,
	HOSTS_TYPE_WILDCARD_MASK = 1,

	HOSTS_TYPE_A = 1 << 1,
	HOSTS_TYPE_A_W = HOSTS_TYPE_A | HOSTS_TYPE_WILDCARD_MASK,

	HOSTS_TYPE_AAAA = 1 << 2,
	HOSTS_TYPE_AAAA_W = HOSTS_TYPE_AAAA | HOSTS_TYPE_WILDCARD_MASK,

	HOSTS_TYPE_CNAME = 1 << 3,
	HOSTS_TYPE_CNAME_W = HOSTS_TYPE_CNAME | HOSTS_TYPE_WILDCARD_MASK,

	HOSTS_TYPE_DISABLED = 1 << 4,
	HOSTS_TYPE_DISABLED_W = HOSTS_TYPE_DISABLED | HOSTS_TYPE_WILDCARD_MASK

}HostsRecordType;

static BOOL ContainWildCard(const char *item)
{
	if( strchr(item, '?') != NULL || strchr(item, '*') != NULL )
	{
		return TRUE;
	} else {
		return FALSE;
	}
}

static HostsRecordType Edition(const char *item)
{
	HostsRecordType WildCard;

	if( item == NULL )
	{
		return HOSTS_TYPE_UNKNOWN;
	}

	for(; isspace(*item); ++item);

	/* Check if it is a Hosts item */
	if( strchr(item, ' ') == NULL && strchr(item, '\t') == NULL )
	{
		return HOSTS_TYPE_UNKNOWN;
	}

	if( *item == '@' )
	{
		if( ContainWildCard(item + 1) )
		{
			return HOSTS_TYPE_DISABLED_W;
		} else {
			return HOSTS_TYPE_DISABLED;
		}
	}

	/* Check if it contain wildcard */
	if( ContainWildCard(item) )
	{
		WildCard = HOSTS_TYPE_WILDCARD_MASK;
	} else {
		WildCard = HOSTS_TYPE_UNKNOWN;
	}

	/* Check if it is IPv6 */
	if( strchr(item, ':') != NULL )
	{
		return HOSTS_TYPE_AAAA | WildCard;
	}

	/* Check if it is CNAME */
	for(; !isspace(*item) ; ++item)
	{
		if( isalpha(*item) )
		{
			return HOSTS_TYPE_CNAME | WildCard;
		}
	}

	/* IPv4 is left */
	return HOSTS_TYPE_A | WildCard;
}

static void GetCount(	FILE *fp,
						int *IPv4,
						int *IPv6,
						int *IPv4W,
						int *IPv6W,
						int *CName,
						int *CNameW,
						int *Disabled,
						int *DisabledW
						)
{
	char			Buffer[320];
	ReadLineStatus	Status;

	*IPv4 = 0;
	*IPv6 = 0;
	*IPv4W = 0;
	*IPv6W = 0;
	*CName = 0;
	*CNameW = 0;
	*Disabled = 0;
	*DisabledW = 0;

	if( fp != NULL )
	{
		while(1)
		{
			Status = ReadLine(fp, Buffer, sizeof(Buffer));
	READDONE:
			if( Status == READ_FAILED_OR_END )
				break;

			switch( Edition(Buffer) )
			{
				case HOSTS_TYPE_AAAA:
					++(*IPv6);
					break;
				case HOSTS_TYPE_AAAA_W:
					++(*IPv6W);
					break;
				case HOSTS_TYPE_A:
					++(*IPv4);
					break;
				case HOSTS_TYPE_A_W:
					++(*IPv4W);
					break;
				case HOSTS_TYPE_CNAME:
					++(*CName);
					break;
				case HOSTS_TYPE_CNAME_W:
					++(*CNameW);
					break;
				case HOSTS_TYPE_DISABLED:
					++(*Disabled);
					break;
				case HOSTS_TYPE_DISABLED_W:
					++(*DisabledW);
					break;
				default:
					break;
			}

			if( Status == READ_TRUNCATED )
			{
				while( Status == READ_TRUNCATED )
					Status = ReadLine(fp, Buffer, sizeof(Buffer));
				goto READDONE;
			}
		}
		fseek(fp, 0, SEEK_SET);
	}

	if( AppendedNum > 0 )
	{
		const char *Appended;

		for(Appended = StringList_GetNext(&AppendedHosts, NULL); Appended != NULL; Appended = StringList_GetNext(&AppendedHosts, Appended))
		{
			switch( Edition(Appended) )
			{
				case HOSTS_TYPE_AAAA:
					++(*IPv6);
					break;
				case HOSTS_TYPE_AAAA_W:
					++(*IPv6W);
					break;
				case HOSTS_TYPE_A:
					++(*IPv4);
					break;
				case HOSTS_TYPE_A_W:
					++(*IPv4W);
					break;
				case HOSTS_TYPE_CNAME:
					++(*CName);
					break;
				case HOSTS_TYPE_CNAME_W:
					++(*CNameW);
					break;
				case HOSTS_TYPE_DISABLED:
					++(*Disabled);
					break;
				case HOSTS_TYPE_DISABLED_W:
					++(*DisabledW);
					break;
				default:
					break;
			}
		}
	}
}

static int InitHostsContainer(	int IPv4Count,
								int IPv6Count,
								int IPv4WCount,
								int IPv6WCount,
								int CNameCount,
								int CNameWCount,
								int DisabledCount,
								int DisabledCountW
								)
{
	if( HashTable_Init(&A, sizeof(Host4), IPv4Count) != 0 )
	{
		return 1;
	}
	if( HashTable_Init(&AAAA, sizeof(Host6), IPv6Count) != 0 )
	{
		return 2;
	}
	if( HashTable_Init(&CName, sizeof(HostCName), CNameCount) != 0 )
	{
		return 3;
	}
	if( HashTable_Init(&Disabled, sizeof(HostDisabled), DisabledCount) != 0 )
	{
		return 4;
	}

	if( Array_Init(&AW, sizeof(Host4), IPv4WCount, FALSE, NULL) != 0 )
	{
		return 5;
	}
	if( Array_Init(&AAAAW, sizeof(Host6), IPv6WCount, FALSE, NULL) != 0 )
	{
		return 6;
	}
	if( Array_Init(&CNameW, sizeof(HostCName), CNameWCount, FALSE, NULL) != 0 )
	{
		return 6;
	}
	if( Array_Init(&DisabledW, sizeof(HostDisabled), DisabledCountW, FALSE, NULL) != 0 )
	{
		return 7;
	}

	if( StringList_Init(&StringChunk, NULL, ',') != 0 )
	{
		return 8;
	}
	return 0;
}

static void FreeHostsContainer(void)
{
	HashTable_Free(&A);
	HashTable_Free(&AAAA);
	HashTable_Free(&CName);
	HashTable_Free(&Disabled);
	Array_Free(&AW);
	Array_Free(&AAAAW);
	Array_Free(&CNameW);
	Array_Free(&DisabledW);
	StringList_Free(&StringChunk);
}

static int AddHosts(char *src)
{
	Host4		tmp4;
	Host6		tmp6;
	HostCName	tmpC;
	HostDisabled	tmpD;
	char		*itr;

	switch( Edition(src) )
	{
		case HOSTS_TYPE_UNKNOWN:
			ERRORMSG("Unrecognisable host : %s\n", src);
			return 1;
			break;

		case HOSTS_TYPE_AAAA:

			for(itr = src; !isspace(*itr); ++itr);
			*itr = '\0';
			for(++itr; isspace(*itr); ++itr);

			if( strlen(itr) > DOMAIN_NAME_LENGTH_MAX )
			{
				return -1;
			}
			tmp6.Domain = StringList_Add(&StringChunk, itr);

			IPv6AddressToNum(src, tmp6.IP);

			HashTable_Add(&AAAA, itr, &tmp6);

			break;

		case HOSTS_TYPE_AAAA_W:

			for(itr = src; !isspace(*itr); ++itr);
			*itr = '\0';
			for(++itr; isspace(*itr); ++itr);

			if( strlen(itr) > DOMAIN_NAME_LENGTH_MAX )
			{
				return -1;
			}
			tmp6.Domain = StringList_Add(&StringChunk, itr);

			IPv6AddressToNum(src, tmp6.IP);

			Array_PushBack(&AAAAW, &tmp6, NULL);

			break;

		case HOSTS_TYPE_A:
			{
				unsigned long addr;

				for(itr = src; !isspace(*itr); ++itr);
				*itr = '\0';
				for(++itr; isspace(*itr); ++itr);

				if( strlen(itr) > DOMAIN_NAME_LENGTH_MAX )
				{
					return -1;
				}
				tmp4.Domain = StringList_Add(&StringChunk, itr);
				addr = inet_addr(src);
				memcpy(tmp4.IP, &addr, 4);

				HashTable_Add(&A, itr, &tmp4);

			}
			break;

		case HOSTS_TYPE_A_W:
			{
				unsigned long addr;

				for(itr = src; !isspace(*itr); ++itr);
				*itr = '\0';
				for(++itr; isspace(*itr); ++itr);

				if( strlen(itr) > DOMAIN_NAME_LENGTH_MAX )
				{
					return -1;
				}
				tmp4.Domain = StringList_Add(&StringChunk, itr);
				addr = inet_addr(src);
				memcpy(tmp4.IP, &addr, 4);

				Array_PushBack(&AW, &tmp4, NULL);

			}
			break;

		case HOSTS_TYPE_CNAME:
			for(itr = src; !isspace(*itr); ++itr);
			*itr = '\0';
			for(++itr; isspace(*itr); ++itr);

			if( strlen(itr) > DOMAIN_NAME_LENGTH_MAX )
			{
				return -1;
			}
			if( strlen(src) > DOMAIN_NAME_LENGTH_MAX )
			{
				return -1;
			}
			tmpC.CName = StringList_Add(&StringChunk, src);
			tmpC.Domain = StringList_Add(&StringChunk, itr);

			HashTable_Add(&CName, itr, &tmpC);

			break;

		case HOSTS_TYPE_CNAME_W:
			for(itr = src; !isspace(*itr); ++itr);
			*itr = '\0';
			for(++itr; isspace(*itr); ++itr);

			if( strlen(itr) > DOMAIN_NAME_LENGTH_MAX )
			{
				return -1;
			}
			if( strlen(src) > DOMAIN_NAME_LENGTH_MAX )
			{
				return -1;
			}
			tmpC.CName = StringList_Add(&StringChunk, src);
			tmpC.Domain = StringList_Add(&StringChunk, itr);

			Array_PushBack(&CNameW, &tmpC, NULL);
			break;

		case HOSTS_TYPE_DISABLED:
			for(itr = src; !isspace(*itr); ++itr);
			*itr = '\0';
			for(++itr; isspace(*itr); ++itr);

			if( strlen(itr) > DOMAIN_NAME_LENGTH_MAX )
			{
				return -1;
			}
			tmpD.Domain = StringList_Add(&StringChunk, itr);

			HashTable_Add(&Disabled, itr, &tmpD);

			break;

		case HOSTS_TYPE_DISABLED_W:
			for(itr = src; !isspace(*itr); ++itr);
			*itr = '\0';
			for(++itr; isspace(*itr); ++itr);

			if( strlen(itr) > DOMAIN_NAME_LENGTH_MAX )
			{
				return -1;
			}
			tmpD.Domain = StringList_Add(&StringChunk, itr);
			Array_PushBack(&DisabledW, &tmpD, NULL);

			break;

		default:
			break;
	}
	return 0;
}

static int LoadFileHosts(FILE *fp)
{
	char			Buffer[256];

	ReadLineStatus	Status;

	if( fp == NULL )
	{
		return 1;
	}

	while(TRUE)
	{
		Status = ReadLine(fp, Buffer, sizeof(Buffer));
SWITCH:
		switch(Status)
		{
			case READ_FAILED_OR_END:
				goto DONE;

			case READ_DONE:
                {
                    char *itr;

                    for(itr = Buffer + strlen(Buffer) - 1; (*itr == '\r' || *itr == '\n') && itr != Buffer; --itr)
                        *itr = '\0';
                }

				AddHosts(Buffer);

				break;

			case READ_TRUNCATED:
				if( strlen(Buffer) > sizeof(Buffer) - 1 )
				{
					ERRORMSG("Hosts Item is too long : %s\n", Buffer);
					do
					{
						Status = ReadLine(fp, Buffer, sizeof(Buffer));
					}
					while( Status == READ_TRUNCATED );
					goto SWITCH;
				}
				break;
		}
	}
DONE:
	return 0;
}

static int LoadAppendHosts(void)
{
	if( AppendedNum > 0 )
	{
		const char *Appended;
		char Changable[256];

		for(Appended = StringList_GetNext(&AppendedHosts, NULL); Appended != NULL; Appended = StringList_GetNext(&AppendedHosts, Appended))
		{
			Changable[sizeof(Changable) - 1] = '\0';
			strncpy(Changable, Appended, sizeof(Changable));
			if( Changable[sizeof(Changable) - 1] == '\0' )
			{
				AddHosts(Changable);
			}
		}
	}
	return 0;
}

static int LoadHosts(void)
{
	FILE	*fp;
	int		Status = 0;

	int		IPv4Count, IPv6Count, CNameCount, DisabledCount;
	int		IPv4WCount, IPv6WCount, CNameWCount, DisabledCountW;


	if( File != NULL)
	{
		fp = fopen(File, "r");
	} else {
		fp = NULL;
	}

	GetCount(fp, &IPv4Count, &IPv6Count, &IPv4WCount, &IPv6WCount, &CNameCount, &CNameWCount, &DisabledCount, &DisabledCountW);

	if( InitHostsContainer(IPv4Count, IPv6Count, IPv4WCount, IPv6WCount, CNameCount, CNameWCount, DisabledCount, DisabledCountW) != 0 )
	{
		if( fp != NULL)
		{
			fclose(fp);
		}
		return 1;
	}

	if( fp != NULL )
	{
		Status = Status || LoadFileHosts(fp);
	}

	if( AppendedNum > 0 )
	{
		Status = Status || LoadAppendHosts();
	}
	INFO("Loading Hosts done, %d IPv4 Hosts, %d IPv6 Hosts, %d CName Hosts, %d Items denote disabled hosts, %d Hosts containing wildcards.\n",
		IPv4Count + IPv4WCount,
		IPv6Count + IPv6WCount,
		CNameCount + CNameWCount,
		DisabledCount + DisabledCountW,
		IPv4WCount + IPv6WCount + CNameWCount + DisabledCountW);

	return Status;
}

static BOOL NeedReload(void)
{
	if( File == NULL )
	{
		return FALSE;
	}

	if( time(NULL) - LastFlush > FlushTime )
	{

#ifdef WIN32

		static FILETIME	LastFileTime = {0, 0};
		WIN32_FIND_DATA	Finddata;
		HANDLE			Handle;

		Handle = FindFirstFile(File, &Finddata);

		if( Handle == INVALID_HANDLE_VALUE )
		{
			return FALSE;
		}

		if( memcmp(&LastFileTime, &(Finddata.ftLastWriteTime), sizeof(FILETIME)) != 0 )
		{
			LastFlush = time(NULL);
			LastFileTime = Finddata.ftLastWriteTime;
			FindClose(Handle);
			return TRUE;
		} else {
			LastFlush = time(NULL);
			FindClose(Handle);
			return FALSE;
		}

#else /* WIN32 */
		static time_t	LastFileTime = 0;
		struct stat		FileStat;

		if( stat(File, &FileStat) != 0 )
		{

			return FALSE;
		}

		if( LastFileTime != FileStat.st_mtime )
		{
			LastFlush = time(NULL);
			LastFileTime = FileStat.st_mtime;

			return TRUE;
		} else {
			LastFlush = time(NULL);

			return FALSE;
		}

#endif /* WIN32 */
	} else {
		return FALSE;
	}
}

static int TryLoadHosts(void)
{
	if( NeedReload() == TRUE )
	{
		FreeHostsContainer();
		return LoadHosts();
	} else {
		return 0;
	}
}

static void GetHostsFromInternet_Thread(void *Unused)
{
	const char *URL = ConfigGetString(&ConfigInfo, "Hosts");
	const char *Script = ConfigGetString(&ConfigInfo, "HostsScript");
	int			FlushTimeOnFailed = ConfigGetInt32(&ConfigInfo, "HostsFlushTimeOnFailed");

	if( FlushTimeOnFailed < 0 )
	{
		FlushTimeOnFailed = INT_MAX;
	}

	while(1)
	{
		INFO("Getting Hosts From %s ...\n", URL);

		if( GetFromInternet(URL, File) == 0 )
		{
			INFO("Hosts saved at %s.\n", File);

			if( Script != NULL )
			{
				INFO("Running script ...\n");
				system(Script);
			}

			RWLock_WrLock(HostsLock);

			FreeHostsContainer();

			LoadHosts();

			RWLock_UnWLock(HostsLock);

			if( FlushTime < 0 )
			{
				return;
			}

			SLEEP(FlushTime * 1000);

		} else {
			ERRORMSG("Getting Hosts from Internet failed. Waiting %d second(s) for retry.\n", FlushTimeOnFailed);
			SLEEP(FlushTimeOnFailed * 1000);
		}

	}
}

int Hosts_Init(void)
{
	const char	*Path;
	const char	*Appended;

	Path = ConfigGetString(&ConfigInfo, "Hosts");
	Appended = ConfigGetString(&ConfigInfo, "AppendHosts");


	if( Path == NULL && Appended == NULL )
	{
		Inited = FALSE;
		return 0;
	}

	FlushTime = ConfigGetInt32(&ConfigInfo, "HostsFlushTime");
	RWLock_Init(HostsLock);

	AppendedNum = 0;

	if( Appended != NULL )
	{
		AppendedNum = StringList_Init(&AppendedHosts, Appended, ',');
	}

	if( Path != NULL )
	{
		if( strncmp(Path, "http", 4) != 0 && strncmp(Path, "ftp", 3) != 0 )
		{
			/* Local file */
			File = Path;

			if( LoadHosts() != 0 )
			{
				ERRORMSG("Loading Hosts failed.\n");
				return 1;
			}
		} else {
			/* Internet file */
			File = ConfigGetString(&ConfigInfo, "HostsDownloadPath");
			if( ConfigGetInt32(&ConfigInfo, "HostsFlushTimeOnFailed") < 1)
			{
				ERRORMSG("`HostsFlushTimeOnFailed' is too small (< 1).\n");
				return 1;
			}

			Internet = TRUE;

			if( FileIsReadable(File) || Appended != NULL )
			{
				INFO("Loading the existing Hosts ...\n");
			}
			LoadHosts();
			CREATE_THREAD(GetHostsFromInternet_Thread, NULL, GetHosts_Thread);
		}

	} else {
		File = NULL;
		LoadHosts();
	}

	LastFlush = time(NULL);
	srand(time(NULL));
	Inited = TRUE;
	return 0;

}

BOOL Hosts_IsInited(void)
{
	return Inited;
}

static Host4 *FindFromA(char *Name)
{
	Host4 *h = NULL;

	do{
		h = (Host4 *)HashTable_Get(&A, Name, h);
		if( h == NULL )
		{
			return NULL;
		}
		if( strcmp(Name, StringList_GetByOffset(&StringChunk, h -> Domain)) == 0 )
		{
			return h;
		}
	}while(TRUE);
}

static Host6 *FindFromAAAA(char *Name)
{
	Host6 *h = NULL;

	do{
		h = (Host6 *)HashTable_Get(&AAAA, Name, h);
		if( h == NULL )
		{
			return NULL;
		}

		if( strcmp(Name, StringList_GetByOffset(&StringChunk, h -> Domain)) == 0 )
		{
			return h;
		}

	}while(TRUE);
}

static Host4 *FindFromAW(char *Name)
{
	int i = 0;
	Host4 *h;
	h = Array_GetBySubscript(&AW, i);
	while( h != NULL )
	{
		if( WILDCARD_MATCH(StringList_GetByOffset(&StringChunk, h -> Domain), Name) == WILDCARD_MATCHED )
			return h;

		h = Array_GetBySubscript(&AW, ++i);
	}

	return NULL;
}

static Host6 *FindFromAAAAW(char *Name)
{
	int i = 0;
	Host6 *h;
	h = Array_GetBySubscript(&AAAAW, i);
	while( h != NULL )
	{
		if( WILDCARD_MATCH(StringList_GetByOffset(&StringChunk, h -> Domain), Name) == WILDCARD_MATCHED )
			return h;

		h = Array_GetBySubscript(&AAAAW, ++i);
	}

	return NULL;
}

static HostCName *FindFromCName(char *Name)
{
	HostCName *h = NULL;

	do{
		h = (HostCName *)HashTable_Get(&CName, Name, h);
		if( h == NULL )
		{
			return NULL;
		}

		if( strcmp(Name, StringList_GetByOffset(&StringChunk, h -> Domain)) == 0 )
		{
			return h;
		}

	}while(TRUE);

}

static HostDisabled *FindFromDisabled(char *Name)
{
	HostDisabled *h = NULL;

	do{
		h = (HostDisabled *)HashTable_Get(&Disabled, Name, h);
		if( h == NULL )
		{
			return NULL;
		}

		if( strcmp(Name, StringList_GetByOffset(&StringChunk, h -> Domain)) == 0 )
		{
			return h;
		}

	}while(TRUE);

}

static HostDisabled *FindFromDisabledW(char *Name)
{
	int i = 0;
	HostDisabled *h;
	h = Array_GetBySubscript(&DisabledW, i);
	while( h != NULL )
	{
		if( WILDCARD_MATCH(StringList_GetByOffset(&StringChunk, h -> Domain), Name) == WILDCARD_MATCHED )
			return h;

		h = Array_GetBySubscript(&DisabledW, ++i);
	}

	return NULL;
}

static HostCName *FindFromCNameW(char *Name)
{
	int i = 0;
	HostCName *h;
	h = Array_GetBySubscript(&CNameW, i);
	while( h != NULL )
	{
		if( WILDCARD_MATCH(StringList_GetByOffset(&StringChunk, h -> Domain), Name) == WILDCARD_MATCHED )
			return h;

		h = Array_GetBySubscript(&CNameW, ++i);
	}

	return NULL;
}



#define	MATCH_STATE_PERFECT	0
#define	MATCH_STATE_ONLY_CNAME	1
#define	MATCH_STATE_NONE	(-1)
static int Hosts_Match(char *Name, DNSRecordType Type, void *OutBuffer)
{
	void *Result;

	if( FindFromDisabled(Name) != NULL )
	{
		return MATCH_STATE_NONE;
	} else if( FindFromDisabledW(Name) != NULL )
	{
		return MATCH_STATE_NONE;
	}

	switch( Type )
	{
		case DNS_TYPE_A:
			Result = FindFromA(Name);
			if( Result == NULL )
			{
				Result = FindFromAW(Name);
			}

			if( Result == NULL )
			{
				break;
			}

			memcpy(OutBuffer, ((Host4 *)Result) -> IP, 4);
			return MATCH_STATE_PERFECT;
			break;

		case DNS_TYPE_AAAA:
			Result = FindFromAAAA(Name);
			if( Result == NULL )
			{
				Result = FindFromAAAAW(Name);
			}

			if( Result == NULL )
			{
				break;
			}

			memcpy(OutBuffer, ((Host6 *)Result) -> IP, 16);
			return MATCH_STATE_PERFECT;
			break;

		case DNS_TYPE_CNAME:
			Result = FindFromCName(Name);
			if( Result == NULL )
			{
				Result = FindFromCNameW(Name);
			}

			if( Result == NULL )
			{
				return MATCH_STATE_NONE;
			}

			strcpy(OutBuffer, StringList_GetByOffset(&StringChunk, ((HostCName *)Result) -> CName));
			return MATCH_STATE_PERFECT;
			break;

		default:
			break;
	}

	if( Type != DNS_TYPE_CNAME )
	{
		Result = FindFromCName(Name);
		if( Result == NULL )
		{
			Result = FindFromCNameW(Name);
		}

		if( Result == NULL )
		{
			return MATCH_STATE_NONE;
		}

		strcpy(OutBuffer, StringList_GetByOffset(&StringChunk, ((HostCName *)Result) -> CName));
		return MATCH_STATE_ONLY_CNAME;
	} else {
		return MATCH_STATE_NONE;
	}
}

static int GenerateSingleRecord(DNSRecordType Type, void *HostsItem, ExtendableBuffer *Buffer)
{
	switch( Type )
	{
		case DNS_TYPE_A:
			{
				char	*h = (char *)HostsItem;
				char	*HereSaved;

				HereSaved = ExtendableBuffer_Expand(Buffer, 2 + 2 + 2 + 4 + 2 + 4);

				if( HereSaved == NULL )
				{
					return -1;
				}

				DNSGenResourceRecord(HereSaved + 1, INT_MAX, "", DNS_TYPE_A, DNS_CLASS_IN, 60, h, 4, FALSE);

				HereSaved[0] = 0xC0;
				HereSaved[1] = 0x0C;

/*
				SET_16_BIT_U_INT(HereSaved + 2, DNS_TYPE_A);
				SET_16_BIT_U_INT(HereSaved + 4, DNS_CLASS_IN);
				SET_32_BIT_U_INT(HereSaved + 6, 60);
				SET_16_BIT_U_INT(HereSaved + 10, 4);
				memcpy(HereSaved + 12, h -> IP, 4);
*/

				return 2 + 2 + 2 + 4 + 2 + 4;
			}
			break;

		case DNS_TYPE_AAAA:
			{
				char	*h = (char *)HostsItem;
				char	*HereSaved;

				HereSaved = ExtendableBuffer_Expand(Buffer, 2 + 2 + 2 + 4 + 2 + 16);
				if( HereSaved == NULL )
				{
					return -1;
				}

				DNSGenResourceRecord(HereSaved + 1, INT_MAX, "", DNS_TYPE_AAAA, DNS_CLASS_IN, 60, h, 16, FALSE);

				HereSaved[0] = 0xC0;
				HereSaved[1] = 0x0C;
/*
				SET_16_BIT_U_INT(HereSaved + 2, DNS_TYPE_AAAA);
				SET_16_BIT_U_INT(HereSaved + 4, DNS_CLASS_IN);
				SET_32_BIT_U_INT(HereSaved + 6, 60);
				SET_16_BIT_U_INT(HereSaved + 10, 16);
				memcpy(HereSaved + 12, h -> IP, 16);
*/
				return 2 + 2 + 2 + 4 + 2 + 16;
			}
			break;

		case DNS_TYPE_CNAME:
			{
				char		*h = (char *)HostsItem;
				char		*HereSaved;

				HereSaved = ExtendableBuffer_Expand(Buffer, 2 + 2 + 2 + 4 + 2 + strlen(h) + 2);
				if( HereSaved == NULL )
				{
					return -1;
				}

				DNSGenResourceRecord(HereSaved + 1, INT_MAX, "", DNS_TYPE_CNAME, DNS_CLASS_IN, 60, h, strlen(h) + 1, TRUE);

				HereSaved[0] = 0xC0;
				HereSaved[1] = 0x0C;

				return 2 + 2 + 2 + 4 + 2 + strlen(h) + 2;
			}
			break;

		default:
			return -1;
			break;
	}
}

static int RecursivelyQuery(DNSRecordType Type, void *HostsItem, ExtendableBuffer *Buffer, int *AnswerCount, QueryContext *Context)
{
	char	*h = (char *)HostsItem;

	BOOL	OriCompress = Context -> Compress;

	int		State;

	int		StartOffset = ExtendableBuffer_GetEndOffset(Buffer);
	const char	*StartPos;
	int		EndOffset;
	const char	*AnswerPos;
	int		MoreSpaceNeeded = 0;

	char	*HereSaved;

	HereSaved = ExtendableBuffer_Expand(Buffer, 2 + 2 + 2 + 4 + 2 + strlen(h) + 2);
	if( HereSaved == NULL )
	{
		return -1;
	}

	Context -> Compress = FALSE;

	DNSGenResourceRecord(HereSaved + 1, INT_MAX, "", DNS_TYPE_CNAME, DNS_CLASS_IN, 60, h, strlen(h) + 1, TRUE);

	HereSaved[0] = 0xC0;
	HereSaved[1] = 0x0C;

	Context -> ProtocolToSrc = DNS_QUARY_PROTOCOL_UDP;

	StartOffset = ExtendableBuffer_GetEndOffset(Buffer);

	State = GetAnswersByName(Context, h, Type, Buffer);
	if( State < 0 )
	{
		Context -> Compress = OriCompress;
		return -1;
	}

	StartPos = ExtendableBuffer_GetPositionByOffset(Buffer, StartOffset);

	EndOffset = DNSJumpOverAnswerRecords(StartPos) - ExtendableBuffer_GetData(Buffer);

	(*AnswerCount) = (int)DNSGetAnswerCount(StartPos) + 1;

	ExtendableBuffer_Eliminate(Buffer, EndOffset, StartOffset + State - EndOffset);

	MoreSpaceNeeded = DNSExpandCName_MoreSpaceNeeded(StartPos);
	if( ExtendableBuffer_Expand(Buffer, MoreSpaceNeeded) == NULL )
	{
		Context -> Compress = OriCompress;
		return -1;
	}

	EndOffset += MoreSpaceNeeded;

	StartPos = ExtendableBuffer_GetPositionByOffset(Buffer, StartOffset);

	DNSExpandCName(StartPos);

	AnswerPos = DNSJumpOverQuestionRecords(StartPos);

	ExtendableBuffer_Eliminate(Buffer, StartOffset, AnswerPos - StartPos);

	Context -> Compress = OriCompress;
	return EndOffset - StartOffset - (AnswerPos - StartPos) + (2 + 2 + 2 + 4 + 2 + strlen(h) + 2);
}

static int Hosts_GetByQuestion_Inner(char *Question, ExtendableBuffer *Buffer, int *AnswerCount, QueryContext *Context)
{
	char				Name[260];
	DNSRecordType		Type;
	DNSRecordClass		Class;
	int					MatchState;
	char				Result[DOMAIN_NAME_LENGTH_MAX + 1];

	DNSGetHostName(Question, DNSJumpHeader(Question), Name);

	Class = (DNSRecordClass)DNSGetRecordClass(DNSJumpHeader(Question));

	if( Class != DNS_CLASS_IN )
		return -1;

	Type = (DNSRecordType)DNSGetRecordType(DNSJumpHeader(Question));

	RWLock_RdLock(HostsLock);
	MatchState = Hosts_Match(Name, Type, Result);
	RWLock_UnRLock(HostsLock);

	if( MatchState == MATCH_STATE_NONE )
	{
		return -1;
	}

	if( Internet != TRUE && FlushTime > 0 )
		TryLoadHosts();

	if( MatchState == MATCH_STATE_PERFECT )
	{
		*AnswerCount = 1;
		return GenerateSingleRecord(Type, Result, Buffer);
	} else if ( MatchState == MATCH_STATE_ONLY_CNAME )
	{
		return RecursivelyQuery(Type, Result, Buffer, AnswerCount, Context);
	} else {
		return -1;
	}
}

int Hosts_GetByQuestion(char *Question, ExtendableBuffer *Buffer, int *AnswerCount, QueryContext *Context)
{
	if( Inited == FALSE )
		return -1;

	return Hosts_GetByQuestion_Inner(Question, Buffer, AnswerCount, Context);

}
