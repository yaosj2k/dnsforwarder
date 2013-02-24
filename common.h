#ifndef _COMMON_H_
#define _COMMON_H_

#include <limits.h>

/* There are some differeces between Linux and Windows.
 * For convenience, we defined something here to unify interfaces,
 * but it seems to be not very good. */

#ifdef WIN32 /* For Windows below. */

	#include <stdlib.h>
	#include <winsock2.h> /* fd_set, struct sockaddr_in,  */
	#include <windows.h> /* For many things */
	#include <wininet.h> /* Some internet API, include InternetOpen(), InternetOpenUrl(), etc. */
	#include <Shlwapi.h> /* PathMatchSpec() */
	#include <ws2tcpip.h> /* struct sockaddr_in6 */

	/* In Linux, the last prarmeter of 'send' is mostly MSG_NOSIGNAL(0x4000) (defined in linux headers),
	 * but in Windows, no this macro. And this prarmeter is zero, mostly.
	 * So we define this macro for Windows.
	 */
	#define	MSG_NOSIGNAL	0

	/* The same as MSG_NOSIGNAL, for recvfrom() and accept() */
	typedef	int		socklen_t;

	/* In Windows, the indetifer of a thread is just a 'HANDLE'. */
	typedef	HANDLE	ThreadHandle;
	/* And Mutex */
	typedef	HANDLE	MutexHandle;

	/* Files */
	typedef	HANDLE	FileHandle;
	#define INVALID_FILE	((FileHandle)NULL)
	typedef	HANDLE	MappingHandle;
	#define INVALID_MAP		((MappingHandle)NULL)
	#define INVALID_MAPPING_FILE	(NULL)

    /* TCP_TIME_OUT, used as a return value */
	#define TCP_TIME_OUT	WSAETIMEDOUT

	#define GET_LAST_ERROR()	(WSAGetLastError())
	#define SET_LAST_ERROR(i)	(WSASetLastError(i))

	/* Close a socket */
	#define	CLOSE_SOCKET(s)	(closesocket(s))

	/* Threading */
	#define CREATE_THREAD(func_ptr, para_ptr, result_holder)	(result_holder) = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(func_ptr), (para_ptr), 0, NULL);
	#define EXIT_THREAD(r)	return (r)
	#define DETACH_THREAD(t)	CloseHandle(t)

	/* Mutex */
	#define CREATE_MUTEX(m)		((m) = CreateMutex(NULL, FALSE, NULL))
	#define GET_MUTEX(m)		(WaitForSingleObject((m), INFINITE))
	#define GET_MUTEX_TRY(m)	(WaitForSingleObject((m), 0))
	#define RELEASE_MUTEX(m)	(ReleaseMutex(m))
	#define DESTROY_MUTEX(m)	(CloseHandle(m))
	#define GET_MUTEX_FAILED	WAIT_TIMEOUT /* Used as return value */

	/* CRITICAL_SECTION */
	#define CRITICAL_SECTION_INIT(c, spin_count)	(InitializeCriticalSectionAndSpinCount(&(c), (spin_count)))
	#define ENTER_CRITICAL_SECTION(c)				(EnterCriticalSection(&(c)))
	#define ENTER_CRITICAL_SECTION_TRY(c)			(TryEnterCriticalSection(&(c)))
	#define LEAVE_CRITICAL_SECTION(c)				(LeaveCriticalSection(&(c)))
	#define DELETE_CRITICAL_SECTION(c)				(DeleteCriticalSection(&(c)))

    /* File and mapping handles*/
	#define OPEN_FILE(file)			CreateFile((file), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
	#define CREATE_FILE_MAPPING(handle, size)	CreateFileMapping((handle), NULL, PAGE_READWRITE, 0, size, NULL);
	#define MPA_FILE(handle, size)	MapViewOfFile((handle), FILE_MAP_WRITE, 0, 0, 0)

	#define UNMAP_FILE(start, size)	UnmapViewOfFile(start)
	#define DESTROY_MAPPING(handle)	CloseHandle(handle)
	#define CLOSE_FILE(handle)		CloseHandle(handle)

	#define PATH_SLASH_CH	'\\'
	#define PATH_SLASH_STR	"\\"

    /* Fill Address  */
	#define FILL_ADDR4(addr_struct, family, address_string, port)	(addr_struct).sin_family = (family); \
																	(addr_struct).sin_addr.S_un.S_addr = inet_addr(address_string); \
																	(addr_struct).sin_port = htons(port);
	/* Suspend current thread for some milliseconds */
	#define	SLEEP(i)	(Sleep(i))

	#define GET_TEMP_DIR()	getenv("TEMP")

	#define GET_THREAD_ID()	(GetCurrentThreadId())

	/* Wildcard match function */
	#define WILDCARD_MATCH(p, s)	PathMatchSpec((s), (p))
	#define WILDCARD_MATCHED		TRUE	/* Used as return value */

	typedef short	sa_family_t;
	typedef u_short	in_port_t;


#else /* For Linux below */

	#include <netinet/in.h>	/* For struct 'sockaddr_in' */

	/* For function 'socket', 'bind', 'connect', 'send', 'recv',
	 * 'sendto', 'recvfrom', 'setsockopt', 'shutdown'. */
	#include <sys/socket.h>

	#include <unistd.h>		/* For function 'close' , 'usleep' */
	#include <errno.h>		/* For extern variable 'errno'. */
	#include <arpa/inet.h>	/* For function 'inet_addr'. */
	#include <pthread.h>	/* Multithread support. */

	#include <sys/types.h>	/* struct stat */
	#include <sys/stat.h>	/* stat() */

	#include <sys/mman.h>	/* mmap */
	#include <fcntl.h>

	#include <sys/syscall.h> /* syscall */

	#include <pwd.h>	/* struct passwd */

	#include <fnmatch.h> /* fnmatch() */

	/* In Linux, the type of socket is 'int'. */
	typedef	int			SOCKET;

	/* We use pthread to implement multi threads */
	/* The indetifer of pthread is 'pthread_t'. */
	typedef	pthread_t			ThreadHandle;
	/* And mutex */
	typedef	pthread_mutex_t		MutexHandle;
	/* spin lock */
	typedef	pthread_spinlock_t	SpinHandle;

	/* There are so many HANDLEs are just ints in Linux. */
	typedef	int	FileHandle;	/* The type of return value of open() */
	#define INVALID_FILE	((FileHandle)(-1))

	typedef	int	MappingHandle;
	#define INVALID_MAP		((MappingHandle)(-1))
	#define INVALID_MAPPING_FILE	((void *)(-1))

    /* TCP_TIME_OUT, used as a return value */
	#define TCP_TIME_OUT	EAGAIN

	extern	int			errno;
	#define GET_LAST_ERROR()	errno
	#define SET_LAST_ERROR(i)	(errno = (i))

	/* These are defined in 'windows.h'. */
	#define	INVALID_SOCKET	((SOCKET)(~0))
	#define	SOCKET_ERROR	(-1)

	/* Close a socket */
	#define	CLOSE_SOCKET(s)	(close(s))

	/* Boolean */
	#define	BOOL	int
	#define	FALSE	0
	#define	TRUE	(!0)

	/* I don't know if this have a effect in linux. But in windows, this is defined. */
	#define SO_DONTLINGER   ((unsigned int) (~SO_LINGER))

	/* pthread */
	#define CREATE_THREAD(func_ptr, para_ptr, return_value) (pthread_create(&return_value, NULL, (void *(*)())(func_ptr), (para_ptr)))
	#define EXIT_THREAD(r)	pthread_exit(r)
	#define DETACH_THREAD(t)	pthread_detach(t)

    /* mutex */
	#define CREATE_MUTEX(m)		(pthread_mutex_init(&(m), NULL))
	#define GET_MUTEX(m)		(pthread_mutex_lock(&(m)))
	#define GET_MUTEX_TRY(m)	(pthread_mutex_trylock(&(m)))
	#define RELEASE_MUTEX(m)	(pthread_mutex_unlock(&(m)))
	#define DESTROY_MUTEX(m)	(pthread_mutex_destroy(&(m)))
	#define GET_MUTEX_FAILED	(!0)

	/* spin lock */
	#define CREATE_SPIN(s)		(pthread_spin_init(&(s), PTHREAD_PROCESS_PRIVATE))
	#define LOCK_SPIN(s)		(pthread_spin_lock(&(s)))
	#define LOCK_SPIN_TRY(s)	(pthread_spin_trylock(&(s)))
	#define UNLOCK_SPIN(s)		(pthread_spin_unlock(&(s)))
	#define DESTROY_SPIN(s)		(pthread_spin_destroy(&(s)))

    /* File and Mapping */
    /* In Linux, there is no a long process to map a file like Windows. */
	#define OPEN_FILE(file)						(open((file), O_RDWR | O_CREAT, S_IRWXU))
	#define CREATE_FILE_MAPPING(handle, size)	(lseek((handle), size, SEEK_SET), write((handle), "\0", 1), (handle))
	#define MPA_FILE(handle, size)				(mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, (handle), 0))
	#define UNMAP_FILE(start, size)				(munmap(start, size))
	#define DESTROY_MAPPING(handle)				/* Nothing */
	#define CLOSE_FILE(handle)					(close(handle))

	#define PATH_SLASH_CH	'/'
	#define PATH_SLASH_STR	"/"

	#define FILL_ADDR4(addr_struct, family, address_string, port)	(addr_struct).sin_family = (family); \
																	(addr_struct).sin_addr.s_addr = inet_addr(address_string); \
																	(addr_struct).sin_port = htons(port);

	#define	SLEEP(i)	(usleep((i) * 1000))

    /* As the name suggests */
	#define GET_TEMP_DIR()	"/tmp"

	#define GET_THREAD_ID()	syscall(__NR_gettid)

	#define WILDCARD_MATCH(p, s)	fnmatch((p), (s), FNM_NOESCAPE)
	#define WILDCARD_MATCHED	0

#endif /* WIN32 */

#define INVALID_THREAD	((ThreadHandle)NULL)

/* Unified interfaces end */

/* something is STILL on some state */
#define __STILL

/* As the name suggests */
#if (INT_MAX == 2147483647)
	#define _32BIT_INT		int
	#define _32BIT_UINT		unsigned int
	#define _32BIT_UINT_MAX	0xFFFFFFFF
#endif

#if (SHRT_MAX == 32767)
	#define _16BIT_INT	short
	#define _16BIT_UINT	unsigned short
#endif

/* Parameters' tag */
#ifndef __in
	#define __in
#endif /* __in */

#ifndef __in_opt
	#define __in_opt
#endif /* __in_opt */

#ifndef __out
	#define __out
#endif /* __out */

#ifndef __out_opt
	#define __out_opt
#endif /* __out_opt */

#ifndef __inout
	#define __inout
#endif /* __inout */

#ifndef __inout_opt
	#define __inout_opt
#endif /* __inout_opt */

#define LENGTH_OF_IPV6_ADDRESS_ASCII	40

typedef union _CompatibleAddr{
	struct sockaddr_in	Addr4;
	struct sockaddr_in6	Addr6;
} CompatibleAddr;

#endif /* _COMMON_H_ */
