/*
tweetnacl의 의존성. 랜덤한 엔트로피를 반환해야 한다.
엔트로피를 읽을 수 없으면 치명적인 오류이다. 일반적인 운영체제에서는 이런 일이 발생하지 않지만...
(왜냐하면 처음에 엔트로피를 충분히 읽어 들인 뒤에 그걸 가지고 CSPRNG로 섞기 때문)
*/

#include <stdlib.h>

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef BOOLEAN (APIENTRY *RtlGenRandom_t)(void*, ULONG);

static HMODULE lib;
static RtlGenRandom_t RtlGenRandom;

static void randombytes_fini(void)
{
	FreeLibrary(lib);
}

static BOOL CALLBACK randombytes_init(PINIT_ONCE initOnce, PVOID param, PVOID *context)
{
	(void)initOnce;
	(void)param;
	(void)context;

	lib = LoadLibraryW(L"ADVAPI32.DLL");
	if (!lib) abort();

	/* RtlGenRandom @ advapi32 = CryptGenRandom @ cryptapi */
	/* 비공개 함수지만 정적으로 링크되어 있어서 사실상 바뀔 가능성이 없어서 널리 쓰임 */
	RtlGenRandom = (RtlGenRandom_t) GetProcAddress(lib, "SystemFunction036");
	if (!RtlGenRandom) {
		FreeLibrary(lib);
		abort();
	}

	atexit(randombytes_fini);
	return TRUE;
}

void randombytes(unsigned char *buf, unsigned long long len)
{
	static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
	InitOnceExecuteOnce(&once, randombytes_init, NULL, NULL);

	RtlGenRandom(buf, (ULONG)len);
}

#else

/* TODO: 리눅스 getrandom(2)을 쓰도록 고치기 */

#include <stdio.h>
#include <pthread.h>

static FILE *urandom;

static void randombytes_fini(void)
{
	fclose(urandom);
}

static void randombytes_init(void)
{
	/* /dev/random을 쓰지 않는다. http://www.2uo.de/myths-about-urandom/ */
	urandom = fopen("/dev/urandom", "rb");
	if (!urandom) abort();

	atexit(randombytes_fini);
}

void randombytes(unsigned char *buf, unsigned long long len)
{
	static pthread_once_t once = PTHREAD_ONCE_INIT;
	pthread_once(&once, randombytes_init);

	if (fread(buf, (size_t)len, 1, urandom) == 0) {
		abort();
	}
}

#endif
