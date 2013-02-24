#include <string.h>
#include <time.h>
#include "excludedlist.h"
#include "querydnsbase.h"
#include "utils.h"
#include "downloader.h"
#include "readline.h"
#include "array.h"
#include "common.h"
#include "rwlock.h"

static int			*DisabledTypes	=	NULL;
static StringList	DisabledDomains;
static Array		PositionsOfDisabled;

static StringList	ExcludedDomains;
static Array		PositionsOfExcluded;


static RWLock		ExcludedListLock;

BOOL IsDisabledType(int Type){
	int *Itr;

	if( DisabledTypes == NULL )
	{
		return FALSE;
	}

	for(Itr = DisabledTypes; *Itr != 0; ++Itr){
		if(*Itr == Type)
		{
			return TRUE;
		}
	}

	return FALSE;
}

BOOL IsDisabledDomain(const char *Domain){
	const char *Itr;
	int loop;
	int	Count;

	Count = Array_GetUsed(&PositionsOfDisabled);

	for(loop = 0; loop != Count; ++loop){
		Itr = *(char **)Array_GetBySubscript(&PositionsOfDisabled, loop);
		if( Itr != NULL )
		{
			if( strchr(Itr, '*') != NULL || strchr(Itr, '?') != NULL  )
			{
				if( WILDCARD_MATCH(Itr, Domain) == WILDCARD_MATCHED )
				{
					return TRUE;
				}
			} else {
				if( strcmp(Itr, Domain + (strlen(Domain) - strlen(Itr))) == 0 )
				{
					return TRUE;
				}
			}
		}
	}

	return FALSE;
}

BOOL IsExcludedDomain(const char *Domain)
{
	const char *Itr;
	int loop;
	int	Count;

	RWLock_RdLock(ExcludedListLock);

	Count = Array_GetUsed(&PositionsOfExcluded);

	for(loop = 0; loop != Count; ++loop){
		Itr = *(char **)Array_GetBySubscript(&PositionsOfExcluded, loop);
		if( Itr != NULL )
		{
			if( strchr(Itr, '*') != NULL || strchr(Itr, '?') != NULL  )
			{
				if( WILDCARD_MATCH(Itr, Domain) == WILDCARD_MATCHED )
				{
					RWLock_UnRLock(ExcludedListLock);
					return TRUE;
				}
			} else {
				if( strcmp(Itr, Domain + (strlen(Domain) - strlen(Itr))) == 0 )
				{
					RWLock_UnRLock(ExcludedListLock);
					return TRUE;
				}
			}
		}
	}

	RWLock_UnRLock(ExcludedListLock);
	return FALSE;
}

static int DisableType(void)
{
	int loop, Count = 1;
	char Tmp[10], *TmpItr;
	const char *Types = ConfigGetString(&ConfigInfo, "DisabledType");

	if(Types == NULL) return 0;

	for(loop = 0; Types[loop] != '\0'; ++loop)
		if(Types[loop] == ',') ++Count;

	DisabledTypes = (int *)SafeMalloc((Count + 1) * sizeof(*(DisabledTypes)));
	DisabledTypes[Count--] = 0;

	for(loop = 0, TmpItr = Tmp; ; ++loop){
		if(Types[loop] == '\0'){
			*TmpItr = '\0';
			DisabledTypes[Count--] = atoi(Tmp);
			break;
		}
		if(Types[loop] != ',')
			*TmpItr++ = Types[loop];
		else{
			*TmpItr = '\0';
			DisabledTypes[Count--] = atoi(Tmp);
			TmpItr = Tmp;
		}
	}
	return 0;
}

static int LoadDomains(StringList *List, const char *Domains)
{
	if( StringList_Init(List, Domains, ',') >= 0 )
		return -1;
	else
		return 0;
}


static BOOL ParseGfwListItem(char *Item)
{
	if( strchr(Item, '/') != NULL || strchr(Item, '*') != NULL || *Item == '@' || strchr(Item, '?') != NULL || *Item == '!' || strchr(Item, '.') == NULL || *Item == '[' )
	{
		return FALSE;
	}

	if( *Item == '|' )
	{
		for(++Item; *Item == '|'; ++Item);
	}

	if( *Item == '.' )
	{
		++Item;
	}

	if( StringList_Find(&ExcludedDomains, Item) == NULL )
	{
		StringList_Add(&ExcludedDomains, Item);
		return TRUE;
	} else {
		return FALSE;
	}

}

static int LoadGfwListFile(const char *File)
{
	FILE	*fp = fopen(File, "r");
	ReadLineStatus Status;
	char	Buffer[64];
	int		Count = 0;

	if( fp == NULL )
	{
		return -1;
	}

	while(TRUE)
	{
		Status = ReadLine(fp, Buffer, sizeof(Buffer));

		switch(Status)
		{
			case READ_FAILED_OR_END:
				goto DONE;
				break;

			case READ_DONE:
				if( ParseGfwListItem(Buffer) == TRUE )
				{
					++Count;
				}
				break;

			case READ_TRUNCATED:
				ReadLine_GoToNextLine(fp);
				break;
		}
	}

DONE:
	fclose(fp);

	return Count;

}

static int InitPositionsArray(Array *a, StringList *s)
{
	const char *Ptr = NULL;
	if( Array_Init(a, sizeof(const char *), StringList_Count(s), FALSE, NULL) != 0 )
	{
		return -1;
	}

	for(Ptr = StringList_GetNext(s, Ptr); Ptr != NULL; Ptr = StringList_GetNext(s, Ptr))
	{
		Array_PushBack(a, &Ptr, NULL);
	}

	return 0;
}

int LoadGfwList_Thread(void *Unused)
{
	int	FlushTime = ConfigGetInt32(&ConfigInfo, "GfwListFlushTime");
	int	FlushTimeOnFailed = ConfigGetInt32(&ConfigInfo, "GfwListFlushTimeOnFailed");

	const char	*GfwList	=	ConfigGetString(&ConfigInfo, "GfwList");
	const char	*ExcludedList	=	ConfigGetString(&ConfigInfo, "ExcludedDomain");
	const char	*File	=	ConfigGetString(&ConfigInfo, "GfwListDownloadPath");
	int			Count;

	if( GfwList == NULL )
	{
		return 0;
	}

	if( FlushTimeOnFailed < 0 )
	{
		FlushTimeOnFailed = INT_MAX;
	}

	while( TRUE )
	{
		INFO("Loading GFW List From %s ...\n", GfwList);
		if( GetFromInternet(GfwList, File) != 0 )
		{
			ERRORMSG("Downloading GFW List failed. Waiting %d second(s) for retry.\n", FlushTimeOnFailed);
			SLEEP(FlushTimeOnFailed * 1000);
		} else {

			INFO("GFW List saved at %s.\n", File);

			if( Base64Decode(File) != 0 )
			{
				ERRORMSG("Decoding GFW List failed. Waiting %d second(s) for retry.\n", FlushTimeOnFailed);
				SLEEP(FlushTimeOnFailed * 1000);
				continue;
			}

			RWLock_WrLock(ExcludedListLock);

			StringList_Free(&ExcludedDomains);
			Array_Free(&PositionsOfExcluded);

			LoadDomains(&ExcludedDomains, ExcludedList);

			Count = LoadGfwListFile(File);
			if( Count < 0 )
			{
				ERRORMSG("Loading GFW List failed, cannot open file %s.\n", File);
				RWLock_UnWLock(ExcludedListLock);
				goto END;
			}

			if( InitPositionsArray(&PositionsOfExcluded, &ExcludedDomains) != 0 )
			{
				RWLock_UnWLock(ExcludedListLock);
				ERRORMSG("Loading GFW List failed. Waiting %d second(s) for retry.\n", FlushTimeOnFailed);
				continue;
			}

			RWLock_UnWLock(ExcludedListLock);
			INFO("Loading GFW List done. %d effective items.\n", Count);
END:
			if( FlushTime < 0 )
			{
				return 0;
			}

			SLEEP(FlushTime * 1000);
		}
	}
}

int LoadGfwList(void)
{
	ThreadHandle gt;
	const char	*GfwList	=	ConfigGetString(&ConfigInfo, "GfwList");
	const char	*File	=	ConfigGetString(&ConfigInfo, "GfwListDownloadPath");
	const char	*ExcludedList	=	ConfigGetString(&ConfigInfo, "ExcludedDomain");
	char		ProtocolStr[8] = {0};
	int			Count;

	strncpy(ProtocolStr, ConfigGetString(&ConfigInfo, "PrimaryServer"), 3);
	StrToLower(ProtocolStr);

	if( GfwList == NULL )
	{
		return 0;
	}

	if( strcmp(ProtocolStr, "udp") != 0 )
	{
		ERRORMSG("Cannot load GFW List when `PrimaryServer' is not udp.\n");
		return -1;
	}

	if( !FileIsReadable(File) )
	{
		goto END;
	}

	INFO("Loading the existing GFW List ...\n");

	RWLock_WrLock(ExcludedListLock);

	StringList_Free(&ExcludedDomains);
	Array_Free(&PositionsOfExcluded);

	LoadDomains(&ExcludedDomains, ExcludedList);

	Count = LoadGfwListFile(File);
	if( Count < 0 )
	{
		RWLock_UnWLock(ExcludedListLock);
		goto END;
	}

	if( InitPositionsArray(&PositionsOfExcluded, &ExcludedDomains) != 0 )
	{
		RWLock_UnWLock(ExcludedListLock);
		goto END;
	}

	RWLock_UnWLock(ExcludedListLock);
	INFO("Loading GFW List done. %d effective items.\n", Count);
END:
	CREATE_THREAD(LoadGfwList_Thread, NULL, gt);

	DETACH_THREAD(gt);

	return 0;
}

int ExcludedList_Init(void)
{
	DisabledTypes = NULL;

	LoadDomains(&DisabledDomains, ConfigGetString(&ConfigInfo, "DisabledDomain"));
	LoadDomains(&ExcludedDomains, ConfigGetString(&ConfigInfo, "ExcludedDomain"));
	DisableType();

	InitPositionsArray(&PositionsOfExcluded, &ExcludedDomains);
	InitPositionsArray(&PositionsOfDisabled, &DisabledDomains);

	RWLock_Init(ExcludedListLock);

	INFO("Excluded & Disabled list initialized.\n");
	return 0;
}
