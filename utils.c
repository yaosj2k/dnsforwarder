#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include "common.h"
#include "utils.h"
#include "dnsgenerator.h"

#ifdef WIN32
	#include <wincrypt.h>
	#ifndef CryptStringToBinary
		BOOL WINAPI CryptStringToBinaryA(const BYTE *,DWORD,DWORD,LPTSTR,DWORD *,DWORD *,DWORD *);
	#define	CryptStringToBinary CryptStringToBinaryA
	#endif /* CryptStringToBinary */
#else
	#include <openssl/bio.h>
	#include <openssl/evp.h>
#endif /* WIN32 */

/* Safe Alloc & Free */
#ifdef WIN32 /* we use critical section */
static CRITICAL_SECTION AllocCS;
#else /* we use spin lock */
static SpinHandle AllocSpin;
#endif /* WIN32 */

void SafeMallocInit(void){
#ifdef WIN32
	CRITICAL_SECTION_INIT(AllocCS, 128);
#else
	CREATE_SPIN(AllocSpin);
#endif /* WIN32 */
}

void *SafeMalloc(size_t Bytes)
{
	void *Result;
#ifdef WIN32
	ENTER_CRITICAL_SECTION(AllocCS);
#else
	LOCK_SPIN(AllocSpin);
#endif /* WIN32 */

	Result = malloc(Bytes);

#ifdef WIN32
	LEAVE_CRITICAL_SECTION(AllocCS);
#else
	UNLOCK_SPIN(AllocSpin);
#endif /* WIN32 */
	return Result;
}

void SafeFree(void *Memory)
{
	if(Memory == NULL)
		return;
#ifdef WIN32
	ENTER_CRITICAL_SECTION(AllocCS);
#else
	LOCK_SPIN(AllocSpin);
#endif /* WIN32 */

	free(Memory);

#ifdef WIN32
	LEAVE_CRITICAL_SECTION(AllocCS);
#else
	UNLOCK_SPIN(AllocSpin);
#endif /* WIN32 */
}

int SafeRealloc(void **Memory_ptr, size_t NewBytes)
{
	void *New;
#ifdef WIN32
	ENTER_CRITICAL_SECTION(AllocCS);
#else
	LOCK_SPIN(AllocSpin);
#endif /* WIN32 */

	New = realloc(*Memory_ptr, NewBytes);

#ifdef WIN32
	LEAVE_CRITICAL_SECTION(AllocCS);
#else
	UNLOCK_SPIN(AllocSpin);
#endif /* WIN32 */

	if(New != NULL)
	{
		*Memory_ptr = New;
		return 0;
	} else {
		return -1;
	}
}

char *StrToLower(char *str)
{
	while( *str != '\0' )
	{
		*str = tolower(*str);
		++str;
	}
	return str;
}

char *BoolToYesNo(BOOL value)
{
	return value == FALSE ? "No" : "Yes";
}

int GetModulePath(char *Buffer, int BufferLength)
{
#ifdef WIN32
	int		ModuleNameLength = 0;
	char	ModuleName[320];
	char	*SlashPosition;

	if( BufferLength < 0 )
		return 0;

	ModuleNameLength = GetModuleFileName(NULL, ModuleName, sizeof(ModuleName) - 1);

	if( ModuleNameLength == 0 )
		return 0;

	SlashPosition = strrchr(ModuleName, '\\');

	if( SlashPosition == NULL )
		return 0;

	*SlashPosition = '\0';

	strncpy(Buffer, ModuleName, BufferLength - 1);
	Buffer[BufferLength - 1] = '\0';

	return strlen(Buffer);
#else
#warning Implement this
#endif
}

int GetErrorMsg(int Code, char *Buffer, int BufferLength)
{

	if( BufferLength < 0 || Buffer == NULL )
	{
		return 0;
	}

#ifdef WIN32
	return FormatMessage(	FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
							NULL,
							Code,
							MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
							Buffer,
							BufferLength,
							NULL);
#else
	strncpy(Buffer, strerror(Code), BufferLength - 1);
	Buffer[BufferLength - 1] ='\0';
	return strlen(Buffer);

#endif
}

char *GetCurDateAndTime(char *Buffer, int BufferLength)
{
	time_t				rawtime;
	struct tm			*timeinfo;

	*Buffer = '\0';
	*(Buffer + BufferLength - 1) = '\0';

	time(&rawtime);

	timeinfo = localtime(&rawtime);

	strftime(Buffer, BufferLength - 1 ,"%b %d %X ", timeinfo);

	return Buffer;
}

int	Base64Decode(const char *File)
{
#ifdef WIN32
	FILE *fp = fopen(File, "rb");
	long FileSize;
	DWORD OutFileSize = 0;
	char *FileContent;
	char *ResultContent;

	if( fp == NULL )
	{
		return -1;
	}

	if( fseek(fp, 0L, SEEK_END) != 0 )
	{
		fclose(fp);
		return -2;
	}

	FileSize = ftell(fp);

	if( FileSize < 0 )
	{
		fclose(fp);
		return -3;
	}

	if( fseek(fp, 0L, SEEK_SET) != 0 )
	{
		fclose(fp);
		return -4;
	}

	FileContent = SafeMalloc(FileSize);
	if( FileContent == NULL )
	{
		fclose(fp);
		return -5;
	}

	if( fread(FileContent, 1, FileSize, fp) != FileSize )
	{
		SafeFree(FileContent);
		fclose(fp);
		return -6;
	}

	fclose(fp);

	fp = fopen(File, "wb");
	if( fp == NULL )
	{
		SafeFree(FileContent);
		return -7;
	}

	if( CryptStringToBinary((const BYTE *)FileContent, FileSize, 0x00000001, NULL, &OutFileSize, NULL, NULL) != TRUE )
	{
		SafeFree(FileContent);
		fclose(fp);
		return -8;
	}

	ResultContent = SafeMalloc(OutFileSize);
	if( ResultContent == NULL )
	{
		SafeFree(FileContent);
		fclose(fp);
		return -9;
	}


	if( CryptStringToBinary((const BYTE *)FileContent, FileSize, 0x00000001, ResultContent, &OutFileSize, NULL, NULL) != TRUE )
	{
		SafeFree(ResultContent);
		SafeFree(FileContent);
		fclose(fp);
		return -9;
	}

	fwrite(ResultContent, 1, OutFileSize, fp);

	SafeFree(ResultContent);
	SafeFree(FileContent);
	fclose(fp);
	return 0;

#else /* WIN32 */
	BIO *ub64, *bmem;

	FILE *fp = fopen(File, "rb");
	long FileSize;
	int	OutputSize = 0;
	char *FileContent;
	char *ResultContent;

	if( fp == NULL )
	{
		return -1;
	}

	if( fseek(fp, 0L, SEEK_END) != 0 )
	{
		fclose(fp);
		return -2;
	}

	FileSize = ftell(fp);

	if( FileSize < 0 )
	{
		fclose(fp);
		return -3;
	}

	if( fseek(fp, 0L, SEEK_SET) != 0 )
	{
		fclose(fp);
		return -4;
	}

	FileContent = SafeMalloc(FileSize);
	if( FileContent == NULL )
	{
		fclose(fp);
		return -5;
	}

	if( fread(FileContent, 1, FileSize, fp) != FileSize )
	{
		SafeFree(FileContent);
		fclose(fp);
		return -6;
	}

	fclose(fp);

	ub64 = BIO_new(BIO_f_base64());
	if( ub64 == NULL )
	{
		SafeFree(FileContent);
		return -7;
	}

	bmem = BIO_new_mem_buf(FileContent, FileSize);
	if( ub64 == NULL )
	{
		SafeFree(FileContent);
		return -8;
	}

	fp = fopen(File, "wb");
	if( fp == NULL )
	{
		BIO_free_all(bmem);
		SafeFree(FileContent);
		return -9;
	}

	bmem = BIO_push(ub64, bmem);
	if( bmem== NULL )
	{
		SafeFree(FileContent);
		fclose(fp);
		return -10;
	}

	ResultContent = SafeMalloc(FileSize);
	if( ResultContent == NULL )
	{
		BIO_free_all(bmem);
		SafeFree(FileContent);
		fclose(fp);
		return -11;
	}

	OutputSize = BIO_read(bmem, ResultContent, FileSize);
	if( OutputSize < 1 )
	{
		BIO_free_all(bmem);
		SafeFree(ResultContent);
		SafeFree(FileContent);
		fclose(fp);
		return -12;
	}

	fwrite(ResultContent, 1, OutputSize, fp);

	BIO_free_all(bmem);
	SafeFree(ResultContent);
	SafeFree(FileContent);
	fclose(fp);
	return 0;

#endif /* WIN32 */
}

int IPv6AddressToNum(const char *asc, void *Buffer)
{
	_16BIT_INT	*buf_s	=	(_16BIT_INT *)Buffer;
	const char	*itr;

	memset(Buffer, 0, 16);

	for(; isspace(*asc); ++asc);

	if( strstr(asc, "::") == NULL )
	{	/* full format */
		int a[8];
		sscanf(asc, "%x:%x:%x:%x:%x:%x:%x:%x",
				a, a + 1, a + 2, a + 3, a + 4, a + 5, a + 6, a + 7
				);
		SET_16_BIT_U_INT(buf_s, a[0]);
		SET_16_BIT_U_INT(buf_s + 1, a[1]);
		SET_16_BIT_U_INT(buf_s + 2, a[2]);
		SET_16_BIT_U_INT(buf_s + 3, a[3]);
		SET_16_BIT_U_INT(buf_s + 4, a[4]);
		SET_16_BIT_U_INT(buf_s + 5, a[5]);
		SET_16_BIT_U_INT(buf_s + 6, a[6]);
		SET_16_BIT_U_INT(buf_s + 7, a[7]);
	} else {
		/* not full*/

		if( asc[2] == '\0' || isspace(asc[2]) )
		{
			memset(Buffer, 0, 16);
			return 0;
		}

		while(1)
		{
			int a;
			itr = asc;
			asc = strchr(asc, ':');
			if( asc == NULL )
				return 0;

			if( itr == asc )
			{
				break;
			}

			sscanf(itr, "%x:", &a);
			SET_16_BIT_U_INT(buf_s, a);
			++buf_s;
			++asc;
		}
		buf_s = (_16BIT_INT *)Buffer + 7;
		for(; *asc != '\0'; ++asc);
		while(1)
		{
			int a;
			for(itr = asc; *itr != ':'; --itr);

			if( *(itr + 1) == '\0' )
				break;

			sscanf(itr + 1, "%x", &a);
			SET_16_BIT_U_INT(buf_s, a);
			--buf_s;
			asc = itr - 1;

			if( *(itr - 1) == ':' )
				break;
		}
	}
	return 0;
}

sa_family_t GetAddressFamily(const char *Addr)
{
	if( strchr(Addr, '[') != NULL )
	{
		return AF_INET6;
	}

	for(; *Addr != '\0'; ++Addr)
	{
		if( !(isdigit(*Addr) || *Addr == '.' || *Addr == ':') )
		{
			return AF_UNSPEC;
		}
	}

	return AF_INET;
}

int IPv6AddressToAsc(const void *Address, void *Buffer)
{
	sprintf((char *)Buffer, "%x:%x:%x:%x:%x:%x:%x:%x",
		GET_16_BIT_U_INT((const char *)Address),
		GET_16_BIT_U_INT((const char *)Address + 2),
		GET_16_BIT_U_INT((const char *)Address + 4),
		GET_16_BIT_U_INT((const char *)Address + 6),
		GET_16_BIT_U_INT((const char *)Address + 8),
		GET_16_BIT_U_INT((const char *)Address + 10),
		GET_16_BIT_U_INT((const char *)Address + 12),
		GET_16_BIT_U_INT((const char *)Address + 14)

	);

	return 0;
}

int	GetConfigDirectory(char *out)
{
#ifdef WIN32

#else /* WIN32 */
	struct passwd *pw = getpwuid(getuid());
	char *home = pw -> pw_dir;
	*out = '\0';
	if( home == NULL )
		return 1;

	strcpy(out, home);
	strcat(out, "/.dnsforwarder");

	return 0;
#endif /* WIN32 */
}

BOOL FileIsReadable(const char *File)
{
	FILE *fp = fopen(File, "r");

	if( fp == NULL )
	{
		return FALSE;
	} else {
		fclose(fp);
		return TRUE;
	}
}

BOOL IsPrime(int n)
{
	int i;

	if( n < 2 )
	{
		return FALSE;
	}

	if( n == 2 )
	{
		return TRUE;
	}

	if( n % 2 == 0 )
	{
		return FALSE;
	}

	for(i = 3; i < sqrt(n) + 1; i += 2)
	{
		if( n % i == 0 )
		{
			return FALSE;
		}
	}

	return TRUE;
}

int FindNextPrime(int Current)
{
	if( IsPrime(Current) )
	{
		return Current;
	}

	Current = ROUND_UP(Current, 2) + 1;

	do
	{
		if( IsPrime(Current) )
		{
			return Current;
		} else {
			Current += 2;
		}

	} while( TRUE );
}
