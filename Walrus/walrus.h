#ifndef _WALRUS_H_
#define _WALRUS_H_

/*
 * Walrus 웹 인증 라이브러리 (서버).
 * 웹에서 사용할 것을 감안하여 암호 기반 인증을 수행하고, 강하게 해시된 암호를 저장한다.
 * 클라이언트가 약한 암호를 주더라도 공격이 어렵도록 하는 알고리즘을 사용한다.
 *
 * 다음 사항에 유의한다.
 *
 * - 암호 기반 인증은 최선의 인증 방법도, 유일한 방법도 아니다. 다인자 인증을 심각하게 고려할 것.
 *   암호가 없이도 쉽고 안전하게 인증할 수 있다면 암호를 쓰지 않는 것이 더 좋다.
 *
 * - 암호에 길이/문자 조건은 엄금. 정말로 약한 암호를 거절하려면 zxcvbn 등의 알려진 라이브러리를 쓰라.
 *
 * - 클라이언트 자바스크립트는 무조건 안전하게 전달되어야 한다. HTTPS를 사용하고 알려진 지침을 따르라.
 *   Walrus 내부에서도 암호화가 일어나지만 이는 추가적인 조치이며 HTTPS를 대체할 수 없다.
 *
 * - 서버가 여러 대 있을 경우 모든 서버가 같은 키 목록을 들고 있어야 한다.
 *   walrus_rehash를 한 번에 한 서버만 호출할 수 있도록 적절한 동기화 절차를 도입하라.
 *   Redis나 memcached 같은 빠른 데이터베이스에서 매 요청마다 import하는 것도 방법이 될 수 있다.
 *
 * - C 라이브러리를 직접 사용할 경우 walrus_verify_secret가 한 번에 너무 많이 호출될 경우를 감안하라.
 */

#include <stdlib.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WALRUS_API
#define WALRUS_API
#endif

/**
 * 메인 상태. C# 등과는 달리 이 구조체는 오랫동안 메모리에 남아 있는 걸 전제로 설계되었다.
 */
typedef struct walrus walrus;

/**
 * 클라이언트로부터 받은 secret에 대응한다.
 * 이 값은 원래의 walrus가 없어도 존재할 수 있다.
 */
typedef struct walrus_secret walrus_secret;

/**
 * 상태를 만든다.
 * realm은 사이트 별로 유일한 문자열이며, walrus* 내부에 복사된다.
 * 어떤 이유로든 실패하면 NULL을 반환한다.
 *
 * 만들어진 상태는 rehash_interval이 기본값으로 설정되며 키가 하나도 설정되지 않은 상태이다.
 * 따라서 walrus_import_keypairs를 호출하기 전까지 대부분의 함수는 실패한다.
 */
extern WALRUS_API walrus *walrus_new(const char *realm, size_t len);

/**
 * 상태를 제거한다. w는 NULL일 수도 있으며 이 경우 아무 일도 하지 않는다.
 */
extern WALRUS_API void walrus_free(walrus *w);

/**
 * walrus_export_keypairs 및 walrus_get_params 함수에서 할당했던 문자열을 해제한다.
 * buf는 NULL일 수도 있으며 이 경우 아무 일도 하지 않는다.
 *
 * 주의: buf가 NULL이 아닐 경우 무조건 대응되는 상태 w에서 할당되었던 문자열이어야 한다.
 */
extern WALRUS_API void walrus_free_str(walrus *w, char *buf);

/**
 * walrus_rehash가 실행될 주기의 기대값을 설정한다. 단위는 초. 설정된 값을 반환한다.
 * intervalsec이 0이면 기본값(600초)으로 대신 설정된다. 이는 초기 설정값이기도 하다.
 * 호출하는 쪽에서는 대략 이 주기로 walrus_rehash를 호출해야 한다. 그러지 않을 경우 이상적으로 동작하지 않을 수 있다.
 */
extern WALRUS_API unsigned int walrus_set_rehash_interval(walrus *w, unsigned int intervalsec);

/**
 * 해시된 암호를 저장할 때 사용하는 내부 저장 파라미터를 설정한다.
 * 현재 이 파라미터는 공개된 의미가 없으며, 0이 될 수 없다는 점만 보장된다.
 * cost가 0이면 초기값이자 기본값으로 대신 설정된다.
 * 설정된 값을 반환한다. 원래 줬던 cost와 다른 값일 수 있다. 올바르지 않은 파라미터면 0을 반환한다.
 */
extern WALRUS_API unsigned int walrus_set_stretch_cost(walrus *w, unsigned int cost);

/**
 * (now가 설정되었을 경우 해당 시각을 가정하여) 키를 확인하고 필요하면 재생성한다.
 * 셋 중 하나를 반환한다.
 *
 * - WALRUS_REHASH_OK (0): 다른 일을 할 필요 없다.
 * - WALRUS_REHASH_PLEASE_EXPORT (1): 작업을 마쳤는데 키가 재생성되었다.
 *   필요하면 walrus_export_keypairs로 다른 서버에 전파해야 한다.
 *   다른 서버에 새 키를 전파하는 과정은 동기화되어야 하는데 이 라이브러리에서는 다루지 않는다.
 * - WALRUS_REHASH_FAILED (-1): 기타 알 수 없는 이유로 실패했다.
 *
 * 구현 노트:
 * "확인"이라 함은 생성된지 (2 * rehash 주기) 이상 넘어 오래된 키를 제거하는 과정이다.
 * 다만 가용성을 보장하기 위해 가장 최근 키는 지우지 않는다.
 * 가장 최근 키가 생성된지 (rehash 주기)를 넘으면 재생성을 시도한다.
 */
extern WALRUS_API enum walrus_rehash {
	WALRUS_REHASH_OK = 0,
	WALRUS_REHASH_PLEASE_EXPORT = 1,
	WALRUS_REHASH_FAILED = -1,
} walrus_rehash(walrus *w, const time_t *now);

/**
 * 현재 상태에 새로운 키 목록을 들여 온다.
 * stored는 walrus_export_keypairs가 반환했던 문자열이어야 한다.
 * 성공하면 1을, 실패했거나 들여온 키가 없으면 0을 반환한다.
 */
extern WALRUS_API int walrus_import_keypairs(walrus *w, const char *stored, size_t len);

/**
 * 현재 상태의 키 목록을 (아스키 출력 가능한) 문자열로 내보낸다.
 * 문자열은 자체 할당되며, walrus_free_str로 해제되어야 한다.
 * 문자열은 널문자로 끝나지만 이와는 별개로 buflen이 NULL이 아니면* buflen에 널 문자를 제외한 길이가 들어간다.
 * 키가 없다거나 하는 이유로 내보내기에 실패하면 NULL을 반환한다. 이 경우 buflen은 바뀌지 않는다.
 * (이러한 문자열 반환 규약은 다른 함수에서도 공통이다.)
 */
extern WALRUS_API char *walrus_export_keypairs(const walrus *w, size_t *buflen);

/**
* 클라이언트에 전달할 목적으로 가장 최근 키를 (아스키 출력 가능한) 문자열로 내보낸다.
* buflen과 반환값의 규약은 walrus_export_keypairs와 동일하다.
*/
extern WALRUS_API char *walrus_get_params(const walrus *w, size_t *buflen);

/**
 * 클라이언트가 전달한 secret을 복호화 및 인증하려 시도한다.
 * user와 secret은 각각 사용자 아이디와 전달된 secret에 대응한다. 이들은 NULL일 수 없다.
 * 복호화 및 인증에 성공하면 walrus_secret 구조체를 할당해서 반환한다.
 * 복호화 및 인증에 실패했다면 NULL을 반환한다. (이는 클라이언트의 실책이므로 별도 처리를 할 필요가 없다.)
 * 사용 가능한 키가 없는 경우는 인증 실패와 동일한 상황이므로 역시 NULL이 반환된다.
 */
extern WALRUS_API walrus_secret *walrus_decode_secret(const walrus *w, const char *user, size_t userlen, const char *secret, size_t secretlen);

/**
 * secret을 제거한다. ws는 NULL일 수도 있으며 이 경우 아무 일도 하지 않는다.
 */
extern WALRUS_API void walrus_free_secret(walrus_secret *ws);

/**
 * walrus_export_secret 및 walrus_make_result 함수에서 할당했던 문자열을 해제한다.
 * buf는 NULL일 수도 있으며 이 경우 아무 일도 하지 않는다.
 *
 * 주의: buf가 NULL이 아닐 경우 무조건 대응되는 상태 ws에서 할당되었던 문자열이어야 한다.
 */
extern WALRUS_API void walrus_free_secret_str(walrus_secret *ws, char *buf);

/**
 * 주어진 secret이 이전에 walrus_export_secret으로 내보냈던 것과 일치하는지 확인한다.
 * stored는 NULL일 수도 있다. 이 경우 서버가 데이터베이스에서 사용자를 찾지 못 했으나
 * 그 사실을 클라이언트에 알려 주기 싫다는 것으로 판단, 적절한 가짜 값으로 시간을 끈다.
 * 셋 중 하나를 반환한다.
 *
 * - WALRUS_VERIFY_BAD(0): 어떤 이유로든 일치하지 않는다.
 * - WALRUS_VERIFY_OK(1): 일치한다.
 * - WALRUS_VERIFY_OK_BUT_REEXPORT_NEEDED(2): 일치하지만 export를 다시 해 주면 좋겠다.
 *   무작위 대입(brute force) 공격을 막기 위한 내부 저장 파라미터가 바뀌었을 경우 반환되며,
 *   walrus_export_secret으로 새 파라미터로 내보내서 데이터베이스에 저장할 것을 권장한다.
 *   어디까지나 "요청"이므로 파라미터가 바뀔 것 같지 않으면 처리하지 않아도 문제는 없다.
 *
 * 동시성: 이 함수는 내부적으로 메모리를 꽤 할당할 수 있다.
 * 만약 walrus_verify_secret이 (서로 다른 walrus_secret이라도) 동시에 일정 갯수,
 * 이를테면 CPU 코어 갯수 이상 호출될 수 있는 환경이면 별도의 확인이 필요하다.
 */
extern WALRUS_API enum walrus_verify {
	WALRUS_VERIFY_BAD = 0,
	WALRUS_VERIFY_OK = 1,
	WALRUS_VERIFY_OK_BUT_REEXPORT_NEEDED = 2,
} walrus_verify_secret(const walrus_secret *ws, const char *stored, size_t len);

/**
 * 주어진 secret을 저장할 수 있는 (아스키 출력 가능한) 문자열로 내보낸다.
 * buflen과 반환값의 규약은 walrus_export_keypairs와 동일하다.
 */
extern WALRUS_API char *walrus_export_secret(const walrus_secret *ws, size_t *buflen);

/**
 * secret를 줬었던 클라이언트에게 주어진 result를 암호화해서 돌려 준다.
 * result는 통상 추후 클라이언트가 인증에 사용할 임의의 토큰이나, 다른 종류의 데이터여도 무관하다.
 * result는 NULL일 수도 있다. 이 경우 resultlen은 무시되고 빈 문자열이 반환된다.
 * buflen과 반환값의 규약은 walrus_export_keypairs와 동일하다.
 */
extern WALRUS_API char *walrus_make_result(const walrus_secret *ws, const char *result, size_t resultlen, size_t *buflen);

#ifdef __cplusplus
}
#endif

#endif
