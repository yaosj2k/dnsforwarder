#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h> /* exit() */
#include <ctype.h> /* isspace() */

#ifndef WIN32
#include <sys/types.h>
#include <sys/stat.h>
#else /* WIN32 */
#include <curl/curl.h>
#endif /* WIN32 */

#include "dnsrelated.h"
#include "common.h"
#include "utils.h"
#include "readconfig.h"
#include "querydnsinterface.h"

#define VERSION "2.3"

#define PRINT(...)		if(ProgramArgs.ShowMassages == TRUE) printf(__VA_ARGS__);

struct _ProgramArgs
{
	char		*ConfigFile_ptr;
	char		ConfigFile[320];

	BOOL		ShowMassages;
	BOOL		ErrorMessages;

} ProgramArgs = {
	NULL, {0},
	TRUE, TRUE,
};

int DaemonInit()
{
#ifdef WIN32
	char		*CmdLine = GetCommandLine();
	char		ModuleName[320];
	char		*itr;
	char		*NewArguments;

	int			ModuleNameLength;

	BOOL		StartUpStatus;
	STARTUPINFO	StartUpInfo;
	PROCESS_INFORMATION ProcessInfo;

	ModuleNameLength = GetModuleFileName(NULL, ModuleName, sizeof(ModuleName) - 1);

	if( ModuleNameLength == 0 )
	{
		return 1;
	} else {
		ModuleName[sizeof(ModuleName) - 1] = '\0';
	}

	for(; isspace(*CmdLine); ++CmdLine);
	if(*CmdLine == '"')
	{
		itr	=	strchr(++CmdLine, '"');
	} else {
		itr	=	strchr(CmdLine, ' ');
	}

	if( itr != NULL )
		CmdLine = itr + 1;
	else
		return 1;

	for(; isspace(*CmdLine); ++CmdLine);

	NewArguments = SafeMalloc(strlen(ModuleName) + strlen(CmdLine) + 32);
	strcpy(NewArguments, "\"");
	strcat(NewArguments, ModuleName);
	strcat(NewArguments, "\" ");
	strcat(NewArguments, CmdLine);
	itr = strstr(NewArguments + strlen(ModuleName) + 2, "-d");
	*(itr + 1) = 'q';

	StartUpInfo.cb = sizeof(StartUpInfo);
	StartUpInfo.lpReserved = NULL;
	StartUpInfo.lpDesktop = NULL;
	StartUpInfo.lpTitle = NULL;
	StartUpInfo.dwFlags = STARTF_USESHOWWINDOW;
	StartUpInfo.wShowWindow = SW_HIDE;
	StartUpInfo.cbReserved2 = 0;
	StartUpInfo.lpReserved2 = NULL;

	StartUpStatus = CreateProcess(NULL, NewArguments, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &StartUpInfo, &ProcessInfo);

	SafeFree(NewArguments);
	if( StartUpStatus != FALSE )
	{
		printf("deamon process pid : %d\n", (int)(ProcessInfo.dwProcessId));
		exit(0);
	} else {
		return 1;
	}
#else /* WIN32 */

    pid_t	pid;
    if( (pid = fork()) < 0 )
    {
        return 1;
    }
    else
    {
        if(pid != 0)
        {
            printf("deamon process pid : %d\n", pid);
            exit(0);
        }
        setsid();
        umask(0); /* clear file mode creation mask */
        close(0);
        close(1);
        close(2);
        return 0;
    }
#endif /* WIN32 */
}

int ArgParse(int argc, char *argv_ori[])
{
	char **argv = argv_ori;
	++argv;
    while(*argv != NULL)
    {
    	if(strcmp("-h", *argv) == 0)
		{
			printf("DNSforwarder by holmium. Free for non-commercial use. Version "VERSION" .\n\n");
			printf("Usage : %s [args].\n", strrchr(argv_ori[0], PATH_SLASH_CH) == NULL ? argv_ori[0] : strrchr(argv_ori[0], PATH_SLASH_CH) + 1);
			printf(" [args] is case sensitivity and can be zero or more (in any order) of:\n"
				  "  -f <FILE>  Use configuration <FILE> instead of the default one.\n"
				  "  -q         Quiet mode. Do not print any information.\n"
				  "  -e         Only show error messages.\n"
				  "  -d         Daemon mode. Run at background.\n"
				  "  -h         Show this help.\n"
				  "\n"
				  "Output format:\n"
				  " Date & Time [Udp|Tcp|Cache|Hosts|Refused][Client IP][Type in querying][Domain in query] :\n"
				  "    Results\n"
				  );
			exit(0);
		}
        if(strcmp("-q", *argv) == 0)
        {
            ProgramArgs.ShowMassages = FALSE;
            ProgramArgs.ErrorMessages = FALSE;
            ++argv;
            continue;
        }

        if(strcmp("-e", *argv) == 0)
        {
            ProgramArgs.ShowMassages = FALSE;
            ++argv;
            continue;
        }

        if(strcmp("-d", *argv) == 0)
        {
            if(DaemonInit() == 0)
            {
                ProgramArgs.ShowMassages = FALSE;
            } else {
            	printf("Daemon init failed, continuing non-daemon mode.\n");
            }
            ++argv;
            continue;
        }

        if(strcmp("-f", *argv) == 0)
        {
            ProgramArgs.ConfigFile_ptr = *(++argv);
            ++argv;
            continue;
        }

		PRINT("Unrecognisable arg `%s'\n", *argv);
        ++argv;
    }

    return 0;
}

int GetDefaultConfigureFile(char *out)
{
#ifdef WIN32
	if( GetModuleFileName(NULL, out, 319) != 0 )
	{
		out[319] = '\0';
		strcpy(strrchr(out, '\\') + 1, "dnsforwarder.config");
	}

	return 0;
#else /* WIN32 */
	struct passwd *pw = getpwuid(getuid());
	char *home = pw -> pw_dir;
	*out = '\0';
	if( home == NULL )
		return 1;

	strcpy(out, home);
	strcat(out, "/.dnsforwarder/config");
	return 0;
#endif /* WIN32 */
}

int main(int argc, char *argv[])
{
#ifdef WIN32
    WSADATA wdata;
#endif

    int ret = 0;

#ifdef WIN32
    if(WSAStartup(MAKEWORD(2, 2), &wdata) != 0)
        return -1;

	SetConsoleTitle("dnsforwarder");
#elseif
	curl_global_init();
#endif

	SafeMallocInit();

	ArgParse(argc, argv);

	if( ProgramArgs.ConfigFile_ptr == NULL )
	{
		GetDefaultConfigureFile(ProgramArgs.ConfigFile);
		ProgramArgs.ConfigFile_ptr = ProgramArgs.ConfigFile;
	}

    PRINT("DNSforwarder by holmium. Free for non-commercial use. Version "VERSION" .\n\n");

	if( QueryDNSInterfaceInit(ProgramArgs.ConfigFile_ptr, ProgramArgs.ShowMassages, ProgramArgs.ErrorMessages) != 0 )
		goto JustEnd;

	putchar('\n');

	if( QueryDNSInterfaceStart() != 0 )
		goto JustEnd;

	QueryDNSInterfaceWait();

JustEnd:
#ifdef WIN32
    WSACleanup();
#endif
    return ret;
}
/*
          "  -T         Open TCP querying at local, no threads specifier.\n"
          "  -U <NUM>   Set the number of UDP querying's threads,\n"
          "             0 represents not to use UDP (default 2).\n"
          "  -s <IP>    Specify DNS server which uses TCP for querying.\n"
          "  -sp <PORT> Specify TCP server's port to <PORT> (default 53).\n"
          "  -la <IP>   Specify local listening IP (default 127.0.0.1).\n"
          "  -lp <PORT> Specify local port to <PORT> (both UDP and TCP, default 53).\n"
          "\n"
          "Rule settings (Double-dash):\n"
          "  --DisableType <NUM1>,<NUM2>,<NUM3>...\n"
          "      Refuse to query informations with one of those types.\n"
          "      All types can be get by using arg `--PrintAllTypes'.\n"
          "  --DisableDomain <DOMAIN1>,<DOMAIN2>,<DOMAIN3>...\n"
          "      Refuse to query informations with one of those Domains.\n"
          "  --ExcludeDomain <DOMAIN1>,<DOMAIN2>,<DOMAIN3>...\n"
          "      Querying those DOMAINs via UDP instead of TCP.\n"
          "      So arg `--UDPServer' and `--UDPPort' will be essential.\n"
          "  --InternalExList\n"
          "      Use internal excluded domains list (Disabled by default).\n"
          "      The list can be get by using arg `--PrintInExList'.\n"
          "  --UDPServer <IP>\n"
          "      Specify DNS server which uses UDP for querying.\n"
          "  --UDPSPort <PORT>\n"
          "      Specify UDP server's port (default 53).\n"
          "\n"
          "Cache Controllings (Double-dash):\n"
          "  --NoCache         Do not use cache (default using).\n"
          "  --CacheSize <NUM> Specify cache size (in Byte).\n"
          "                    (Default 1048576 Bytes [1MB] ).\n"
          "  --IgnoreTTL       Ignore TTL.\n"
          "                    (do not remove anything from cache, disabled by default)\n"
          "  --ForceTTL <NUM>  Forced let all TTLs be <NUM>,\n"
          "                    instead of their own (default unforced).\n"
          "  --MultiTTL <NUM>  Multiplying TTL by <NUM> (default 1).\n"
          "\n"
          "Infomations (Double-dash):\n"
          "  --PrintAllTypes     Print all known DNS record types.\n"
          "  --PrintInExList     Print all internal excluded domains.\n"
          "\n"
          "Other (Double-dash):\n"
          "  --CustoName <STR>   Customising local server name.\n"
          "\n"
*/
