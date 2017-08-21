#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <tweetnacl/tweetnacl.h>
#include <scrypt/crypto_scrypt.h>
#include "walrus.h"

#ifndef NDEBUG
#define TEST
#endif

#ifdef TEST
#include <stdio.h>

#define CHECK(cond) \
	if (cond) {} else do { \
		fprintf(stderr, "FAILED at %s:%d!\n\t%s is false.\n", __FILE__, __LINE__, #cond); \
		abort(); \
		return 0; \
	} while (0)
#define CHECK_EQ(a, b) \
	if ((a) == (b)) {} else do { \
		fprintf(stderr, "FAILED at %s:%d!\n\t%s != %s.\n", __FILE__, __LINE__, #a, #b); \
		abort(); \
		return 0; \
	} while (0)
#define CHECKF(cond, fmt, ...) \
	if (cond) {} else do { \
		fprintf(stderr, "FAILED at %s:%d!\n\t%s is false: " fmt "\n", __FILE__, __LINE__, #cond, ##__VA_ARGS__); \
		abort(); \
		return 0; \
	} while (0)
#define CHECKF_EQ(a, b, fmt, ...) \
	if ((a) == (b)) {} else do { \
		fprintf(stderr, "FAILED at %s:%d!\n\t%s != %s: " fmt "\n", __FILE__, __LINE__, #a, #b, ##__VA_ARGS__); \
		abort(); \
		return 0; \
	} while (0)

/* 메모리를 넘겨서 쓰는 경우를 체크하기 위한 보조 도구들 */
static unsigned char walrus_random_buf[4096]; /* 나중에 초기화한다 */
#define PREPARE_BUF(buf) \
	do { \
		CHECKF(sizeof(buf) <= sizeof(walrus_random_buf), "walrus_random_buf is too small"); \
		memcpy(buf, walrus_random_buf, sizeof(buf)); \
	} while (0)
#define CHECK_BUF(buf, writtenlen) \
	do { \
		size_t wlen = (writtenlen); \
		CHECKF(wlen <= sizeof(buf), "written size %zd is bigger than buffer size %zd", wlen, sizeof(buf)); \
		CHECKF_EQ(memcmp(buf + wlen, walrus_random_buf + wlen, sizeof(buf) - wlen), 0, "buffer was overwritten past its guarantee"); \
	} while (0)
#endif

/******************************************************************************/
/* 바이트열 조작 */

typedef unsigned char byte_t;

/* 빅 엔디언으로 4바이트를 읽는다. buf[0..3]을 읽을 수 있어야 한다. */
static uint32_t walrus_read_u32(const byte_t *buf)
{
	return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) | ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
}

/* 빅 엔디언으로 8바이트를 읽는다. buf[0..7]을 읽을 수 있어야 한다. */
static uint64_t walrus_read_u64(const byte_t *buf)
{
	return ((uint64_t)walrus_read_u32(buf) << 32) | (uint64_t)walrus_read_u32(buf + 4);
}

/* 빅 엔디언으로 4바이트를 쓴다. buf[0..3]을 쓸 수 있어야 한다. */
static void walrus_write_u32(byte_t *buf, uint32_t v)
{
	buf[0] = (byte_t)(v >> 24);
	buf[1] = (byte_t)(v >> 16);
	buf[2] = (byte_t)(v >> 8);
	buf[3] = (byte_t)v;
}

/* 빅 엔디언으로 8바이트를 쓴다. buf[0..7]을 쓸 수 있어야 한다. */
static void walrus_write_u64(byte_t *buf, uint64_t v)
{
	walrus_write_u32(buf, (uint32_t)(v >> 32));
	walrus_write_u32(buf + 4, (uint32_t)v);
}

#define walrus_read_i32(buf) (int32_t)walrus_read_u32(buf)
#define walrus_read_i64(buf) (int64_t)walrus_read_u64(buf)
#define walrus_write_i32(buf, v) walrus_write_u32(buf, (uint32_t)(v))
#define walrus_write_i64(buf, v) walrus_write_u64(buf, (uint64_t)(v))

/******************************************************************************/
/* base64 */

#define WALRUS_B64_ENCODE_OUTLEN(inlen) (((inlen) + 2) / 3 * 4)
#define WALRUS_B64_DECODE_OUTLEN_MAX(inlen) (((inlen) + 3) / 4 * 3) /* 최대 -3까지 차이날 수 있다. */

/* out에 WALRUS_B64_ENCODE_OUTLEN(inlen)만큼의 메모리가 할당되어 있어야 한다. */
static size_t walrus_b64_encode(char *out, const byte_t *in, size_t inlen)
{
	static const char ALPHABET[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	/* i.e. ceil(inlen / 3) * 4 */
	size_t outlen = (inlen + 2) / 3 * 4;

	assert(out != NULL);
	assert(in != NULL);
	
	while (inlen >= 3) {
		out[0] = ALPHABET[in[0] >> 2];
		out[1] = ALPHABET[((in[0] & 3) << 4) | (in[1] >> 4)];
		out[2] = ALPHABET[((in[1] & 15) << 2) | (in[2] >> 6)];
		out[3] = ALPHABET[in[2] & 63];
		out += 4;
		in += 3;
		inlen -= 3;
	}

	switch (inlen) {
	case 0:
		break;

	case 1:
		out[0] = ALPHABET[in[0] >> 2];
		out[1] = ALPHABET[(in[0] & 3) << 4];
		out[2] = '=';
		out[3] = '=';
		break;

	case 2:
		out[0] = ALPHABET[in[0] >> 2];
		out[1] = ALPHABET[((in[0] & 3) << 4) | (in[1] >> 4)];
		out[2] = ALPHABET[(in[1] & 15) << 2];
		out[3] = '=';
		break;

	default:
		assert(0);
	}

	return outlen;
}

/* out에 WALRUS_B64_DECODE_OUTLEN_MAX(inlen)만큼의 메모리가 할당되어 있어야 한다. 오류가 나면 (size_t)(-1)을 반환. */
static size_t walrus_b64_decode(byte_t *out, const char *in, size_t inlen)
{
#define X 255
	static const byte_t ALPHABET_MAP[256] = {
		 X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,
		 X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,
		 X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X, 62,  X,  X,  X, 63,
		52, 53, 54, 55, 56, 57, 58, 59, 60, 61,  X,  X,  X,  X,  X,  X,
		 X,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
		15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  X,  X,  X,  X,  X,
		 X, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
		41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,  X,  X,  X,  X,  X,
		 X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,
		 X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,
		 X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,
		 X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,
		 X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,
		 X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,
		 X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,
		 X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,  X,
	};
#undef X

	size_t outlen;
	byte_t a, b, c, d;

	/* 항상 pad되어 있다고 가정하므로 4의 배수가 아니면 오류이다. */
	if (inlen == 0) return 0;
	if (inlen % 4 != 0) return (size_t)(-1);
	outlen = inlen / 4 * 3;

	assert(out != NULL);
	assert(in != NULL);

	while (inlen > 4) {
		a = ALPHABET_MAP[in[0]];
		b = ALPHABET_MAP[in[1]];
		c = ALPHABET_MAP[in[2]];
		d = ALPHABET_MAP[in[3]];
		if ((a | b | c | d) > 63) return (size_t)(-1);
		out[0] = (a << 2) | (b >> 4);
		out[1] = (b << 4) | (c >> 2);
		out[2] = (c << 6) | d;
		out += 3;
		in += 4;
		inlen -= 4;
	}

	/* 마지막 chunk만 특수 처리 (를 하기 위하여 inlen == 0 케이스를 앞에서 먼저 체크한다) */
	a = ALPHABET_MAP[in[0]];
	b = ALPHABET_MAP[in[1]];
	c = ALPHABET_MAP[in[2]];
	d = ALPHABET_MAP[in[3]];
	if (in[2] == '=') { /* XX== */
		if ((b & 15) != 0 || in[3] != '=') return (size_t)(-1);
		c = d = 0;
		outlen -= 2;
	} else if (in[3] == '=') { /* XXX= */
		if ((c & 3) != 0) return (size_t)(-1);
		d = 0;
		outlen -= 1;
	}
	if ((a | b | c | d) > 63) return (size_t)(-1);
	out[0] = (a << 2) | (b >> 4);
	out[1] = (b << 4) | (c >> 2); /* out[1]과 out[2]는 안 쓰일 수도 있다. 버퍼는 충분하니 문제 없다. */
	out[2] = (c << 6) | d;
	return outlen;
}

/* walrus_b64_encode를 문자열 반환 컨벤션에 맞춰서 wrap한다 */
static char *walrus_b64_encode_alloc(const byte_t *in, size_t inlen, size_t *buflen)
{
	byte_t *out;
	size_t outlen;

	out = malloc(WALRUS_B64_ENCODE_OUTLEN(inlen) + 1);
	if (out == NULL) return NULL;
	outlen = walrus_b64_encode(out, in, inlen);
	out[outlen] = '\0';
	if (buflen != NULL) *buflen = outlen;
	return out;
}

#ifdef TEST
static int walrus_b64_run_tests(void)
{
	static const struct {
		size_t decodedlen;
		byte_t decoded[6];
		const char *encoded;
	} POSITIVE_TESTS[] = {
		{ 0, { 0 /*dummy*/ }, "" },
		{ 1, { 1 }, "AQ==" },
		{ 1, { 42 }, "Kg==" },
		{ 2, { 0, 255 }, "AP8=" },
		{ 2, { 255, 0 }, "/wA=" },
		{ 3, { 0, 255, 0 }, "AP8A" },
		{ 3, { 255, 0, 255 }, "/wD/" },
		{ 3, { 12, 34, 56 }, "DCI4" },
		{ 4, { 12, 34, 56, 78 }, "DCI4Tg==" },
		{ 5, { 12, 34, 56, 78, 90 }, "DCI4Tlo=" },
		{ 6, { 251, 239, 190, 251, 239, 190 }, "++++++++" },
		{ 6, { 255, 255, 255, 255, 255, 255 }, "////////" },
	};

	static const char *NEGATIVE_TESTS[] = {
		"!",
		"A",
		"B",
		"AB",
		"AP",
		"AAB",
		"AAD",
		"AAD",
		"====",
		"A===",
		"B===",
		"AB==",
		"AP==",
		"AAB=",
		"AAD=",
		"AAD=",
		"AAAA====",
		"AP8=/wA=",
		"AP 8",
		"AP 8=",
	};

	enum { BUFLEN = 64 };

	size_t i;

	/* 매크로 테스트 */
	CHECK_EQ(WALRUS_B64_ENCODE_OUTLEN(0), 0);
	CHECK_EQ(WALRUS_B64_ENCODE_OUTLEN(1), 4);
	CHECK_EQ(WALRUS_B64_ENCODE_OUTLEN(2), 4);
	CHECK_EQ(WALRUS_B64_ENCODE_OUTLEN(3), 4);
	CHECK_EQ(WALRUS_B64_ENCODE_OUTLEN(4), 8);
	CHECK_EQ(WALRUS_B64_ENCODE_OUTLEN(5), 8);
	CHECK_EQ(WALRUS_B64_ENCODE_OUTLEN(6), 8);
	CHECK_EQ(WALRUS_B64_ENCODE_OUTLEN(7), 12);
	CHECK_EQ(WALRUS_B64_DECODE_OUTLEN_MAX(0), 0);
	CHECK_EQ(WALRUS_B64_DECODE_OUTLEN_MAX(1), 3); /* 실제로는 1..3은 padding이 없어 오류지만, 어쨌든 처리한다 */
	CHECK_EQ(WALRUS_B64_DECODE_OUTLEN_MAX(2), 3);
	CHECK_EQ(WALRUS_B64_DECODE_OUTLEN_MAX(3), 3);
	CHECK_EQ(WALRUS_B64_DECODE_OUTLEN_MAX(4), 3);
	CHECK_EQ(WALRUS_B64_DECODE_OUTLEN_MAX(5), 6);
	CHECK_EQ(WALRUS_B64_DECODE_OUTLEN_MAX(6), 6);
	CHECK_EQ(WALRUS_B64_DECODE_OUTLEN_MAX(7), 6);
	CHECK_EQ(WALRUS_B64_DECODE_OUTLEN_MAX(8), 6);
	CHECK_EQ(WALRUS_B64_DECODE_OUTLEN_MAX(9), 9);

	for (i = 0; i < sizeof(POSITIVE_TESTS) / sizeof(*POSITIVE_TESTS); ++i) {
		char encoded[BUFLEN];
		char *encodedptr;
		size_t encodedlen;
		size_t encodedptrlen;
		byte_t decoded[BUFLEN];
		size_t decodedlen;
		size_t decodedbuflen;

		#define MSG "positive test #%zd failed."

		PREPARE_BUF(encoded);
		encodedlen = walrus_b64_encode(encoded, POSITIVE_TESTS[i].decoded, POSITIVE_TESTS[i].decodedlen);
		CHECK_BUF(encoded, encodedlen);
		CHECKF_EQ(encodedlen, strlen(POSITIVE_TESTS[i].encoded), MSG, i);
		CHECKF_EQ(memcmp(encoded, POSITIVE_TESTS[i].encoded, encodedlen), 0, MSG, i);

		encodedptr = walrus_b64_encode_alloc(POSITIVE_TESTS[i].decoded, POSITIVE_TESTS[i].decodedlen, &encodedptrlen);
		CHECKF(encodedptr != NULL, MSG, i);
		CHECKF_EQ(strcmp(encodedptr, POSITIVE_TESTS[i].encoded), 0, MSG, i);
		CHECKF_EQ(encodedptrlen, encodedlen, MSG, i);
		free(encodedptr);

		encodedptr = walrus_b64_encode_alloc(POSITIVE_TESTS[i].decoded, POSITIVE_TESTS[i].decodedlen, NULL);
		CHECKF(encodedptr != NULL, MSG, i);
		CHECKF_EQ(strcmp(encodedptr, POSITIVE_TESTS[i].encoded), 0, MSG, i);
		free(encodedptr);

		PREPARE_BUF(decoded);
		decodedlen = walrus_b64_decode(decoded, encoded, encodedlen);
		CHECKF_EQ(decodedlen, POSITIVE_TESTS[i].decodedlen, MSG, i);
		CHECKF_EQ(memcmp(decoded, POSITIVE_TESTS[i].decoded, decodedlen), 0, MSG, i);
		decodedbuflen = WALRUS_B64_DECODE_OUTLEN_MAX(encodedlen);
		CHECKF(decodedlen <= decodedbuflen, MSG, i);
		CHECK_BUF(decoded, decodedbuflen);

		#undef MSG
	}

	for (i = 0; i < sizeof(NEGATIVE_TESTS) / sizeof(*NEGATIVE_TESTS); ++i) {
		size_t encodedlen;
		byte_t decoded[BUFLEN];
		size_t decodedlen;
		size_t decodedbuflen;

		#define MSG "negative test #%zd failed."

		PREPARE_BUF(decoded);
		encodedlen = strlen(NEGATIVE_TESTS[i]);
		decodedlen = walrus_b64_decode(decoded, NEGATIVE_TESTS[i], encodedlen);
		CHECKF_EQ(decodedlen, (size_t)(-1), MSG, i);
		decodedbuflen = WALRUS_B64_DECODE_OUTLEN_MAX(encodedlen);
		CHECK_BUF(decoded, decodedbuflen);

		#undef MSG
	}

	return 1;
}
#endif /* TEST */

/******************************************************************************/
/* 키 쌍 관리 */

typedef struct walrus_keypair {
	int64_t created;
	byte_t pk[crypto_box_PUBLICKEYBYTES];
	byte_t sk[crypto_box_SECRETKEYBYTES];
} walrus_keypair;

/* 키 쌍 문자열 포맷(base64 이후):
 * - 0..7: int64_t 생성 시각
 * - 8..39: byte_t[32] 비밀키
 *
 * base64된 후의 크기는 56바이트이다.
 * 공개키는 비밀키로부터 생성할 수 있다.
 */

/* 이하 매크로들에서 RAWLEN은 원래 데이터 크기, LEN은 인코딩 후 크기, BUFLEN은 *디코딩에 필요한* 크기이다.
 * RAWLEN <= BUFLEN이기 때문에 메모리 할당할 때는 무조건 BUFLEN을 사용한다. (그깟 메모리 좀 더 쓴다고 문제 없다.)
 * RAWLEN을 써야 할지 LEN을 써야 할 지는 일반적으로 변수명에 raw가 붙어 있는지로 확인하면 된다. */
#define WALRUS_KEYPAIR_RAWLEN (8 + crypto_box_SECRETKEYBYTES)
#define WALRUS_KEYPAIR_LEN WALRUS_B64_ENCODE_OUTLEN(WALRUS_KEYPAIR_RAWLEN)
#define WALRUS_KEYPAIR_BUFLEN WALRUS_B64_DECODE_OUTLEN_MAX(WALRUS_KEYPAIR_LEN)

static void walrus_keypair_generate(walrus_keypair *k, time_t now)
{
	assert(k != NULL);

	crypto_box_keypair(k->pk, k->sk);
	k->created = (int64_t)now; /* 이론적으로는 아닐 수 있는데, 된다고 치자 */
}

/* 한 키 쌍을 파싱한다. (stored는 구분자를 포함하지 않는다.) 성공하면 1을 반환한다. */
static int walrus_keypair_read(walrus_keypair *k, const char *stored, size_t len)
{
	byte_t buf[WALRUS_KEYPAIR_BUFLEN];

	assert(k != NULL);
	assert(stored != NULL);

	if (len < WALRUS_KEYPAIR_LEN) return 0;
	if (walrus_b64_decode(buf, stored, len) != WALRUS_KEYPAIR_RAWLEN) return 0;

	k->created = (time_t)walrus_read_i64(buf); /* 이론적으로는 아닐 수 있는데, 된다고 치자 */
	memcpy(k->sk, buf + 8, crypto_box_SECRETKEYBYTES);
	crypto_scalarmult_base(k->pk, k->sk);
	return 1;
}

/* 한 키 쌍을 출력한다. buf는 최소 WALRUS_KEYPAIR_BUFLEN바이트 이상의 버퍼여야 한다. */
static size_t walrus_keypair_write(const walrus_keypair *k, char *buf)
{
	byte_t raw[WALRUS_KEYPAIR_BUFLEN];

	assert(k != NULL);
	assert(buf != NULL);

	walrus_write_i64(raw, k->created);
	memcpy(raw + 8, k->sk, crypto_box_SECRETKEYBYTES);
	return walrus_b64_encode(buf, raw, WALRUS_KEYPAIR_RAWLEN);
}

#ifdef TEST
static int walrus_keypair_run_tests(void)
{
	enum { BUFLEN = 64 };

	walrus_keypair k1;
	walrus_keypair k2;
	byte_t buf[BUFLEN];
	size_t outlen;

	CHECK(WALRUS_KEYPAIR_LEN < BUFLEN);

	walrus_keypair_generate(&k1, time(NULL));

	PREPARE_BUF(buf);
	outlen = walrus_keypair_write(&k1, buf);
	CHECK_EQ(outlen, WALRUS_KEYPAIR_LEN);
	CHECK_BUF(buf, outlen);

	CHECK(walrus_keypair_read(&k2, buf, outlen));
	CHECK_EQ(k1.created, k2.created);
	CHECK_EQ(memcmp(k1.pk, k2.pk, crypto_box_PUBLICKEYBYTES), 0);
	CHECK_EQ(memcmp(k1.sk, k2.sk, crypto_box_SECRETKEYBYTES), 0);

	CHECK(!walrus_keypair_read(&k2, buf, 0));
	CHECK(!walrus_keypair_read(&k2, buf, outlen + 1));
	CHECK(!walrus_keypair_read(&k2, buf, outlen - 1));

	return 1;
}
#endif /* TEST */

/******************************************************************************/
/* 키 저장 파라미터 관리 */

/* 포맷: 101100MM MMMMrrrr rrpppppp xxxxxxxx
 * x는 무시된다(walrus_read_u32를 쓰기 위함). r과 p는 scrypt의 그것과 같다.
 * M은 (lg N - 3)으로 정의되며, 따라서 메모리 사용량은 (2^M * r) MB가 된다.
 */
typedef uint32_t walrus_stretch_cost;

/* 저장용 키 포맷(base64 이후):
 * - 0..2: byte_t[3] walrus_stretch_cost의 상위 24비트 (빅 엔디안)
 * - 3..34: byte_t[32] 해시
 *
 * base64된 후의 크기는 48바이트이다.
 * walrus_stretch_cost는 base64 첫 글자가 `s`가 되도록 설정되어 있다.
 * 다른 알고리즘을 쓰게 되면 해당 글자가 바뀌게 될 것이므로 구분할 수 있다.
 */

#define WALRUS_STRETCH_COST_RAWLEN 3
#define WALRUS_STRETCH_HASH_RAWLEN 32
#define WALRUS_STRETCH_RAWLEN (WALRUS_STRETCH_COST_RAWLEN + WALRUS_STRETCH_HASH_RAWLEN)
#define WALRUS_STRETCH_LEN WALRUS_B64_ENCODE_OUTLEN(WALRUS_STRETCH_RAWLEN)
#define WALRUS_STRETCH_BUFLEN WALRUS_B64_DECODE_OUTLEN_MAX(WALRUS_STRETCH_LEN)

#define WALRUS_STRETCH_COST(M, r, p) ((uint32_t)0xb0000000 | (((uint32_t)(M) & 31) << 20) | (((uint32_t)(r) & 31) << 14) | (((uint32_t)(p) & 31) << 8))

#define WALRUS_STRETCH_COST_M(cost) (((uint32_t)(cost) >> 20) & 31)
#define WALRUS_STRETCH_COST_R(cost) (((uint32_t)(cost) >> 14) & 31)
#define WALRUS_STRETCH_COST_P(cost) (((uint32_t)(cost) >> 8) & 31)

#define WALRUS_DEFAULT_STRETCH_COST WALRUS_STRETCH_COST(10, 16, 1)

static walrus_stretch_cost walrus_read_stretch_cost(const byte_t *buf)
{
	return walrus_read_u32(buf) & (uint32_t)0xffffff00;
}

/* 정규화된 walrus_stretch_cost 또는 실패시 0을 반환한다. */
static walrus_stretch_cost walrus_stretch_cost_check(walrus_stretch_cost cost, int require_safe, uint64_t *outN, uint32_t *outr, uint32_t *outp)
{
	uint32_t M = WALRUS_STRETCH_COST_M(cost);
	uint32_t r = WALRUS_STRETCH_COST_R(cost);
	uint32_t p = WALRUS_STRETCH_COST_P(cost);

	assert(outN != NULL);
	assert(outr != NULL);
	assert(outp != NULL);

	/* ------------------------------------------------------------ */
	/* 포맷 체크 */

	if ((cost >> 24) != 0xb0) return 0;

	/* r은 1 이상이기만 하면 되므로 포맷에 맞춘다. */
	if (r < 1 || r > 63) return 0;

	/* p는 1 이상 f(r) 미만이어야 하는데, 주어진 r 범위에서 f(r) >> 63이므로 포맷에 맞춘다. */
	if (p < 1 || p > 63) return 0;

	/* lg N은 1 이상 16r 미만이어야 하고, scrypt 라이브러리가 N을 받으므로 N < 2^64여야 한다.
	 * M = lg N - 3으로 조건을 정리하면 아래 수식을 얻음. */
	if (M < 0 || M > 61 || M >= r * 16 - 3) return 0;

	/* ------------------------------------------------------------ */
	/* require_safe가 참이면 너무 낮은 파라미터로 판단하여 리젝한다. */

	if (require_safe) {
		/* 메모리 사용량이 최소 16 MB = 2^14 KB가 되도록 강제한다.
		 * http://blog.ircmaxell.com/2014/03/why-i-dont-recommend-scrypt.html
		 * 원래대로라면 (r << M) < (1 << 14)겠지만 오버플로를 피하려 순서를 뒤바꿈. */
		if (M < 14 && r < (1 << 14 >> M)) return 0;
	}

	/* ------------------------------------------------------------ */
	/* 파라미터를 잘못 설정하면 말도 안 되는 메모리량과 연산량을 필요로 할 수 있으므로,
	 * 말도 안 될 정도로 비싼 파라미터면 실행 자체를 포기한다. */

	/* 메모리 사용량이 1 GB = 2^20 KB 이상이거나... */
	if (M >= 20 || r >= (1 << 20 >> M)) return 0;

	/* 대략적으로 1분 이상 걸릴 것 같으면 때려 친다.
	 * scrypt N=2^14 (M=11) r=8 p=1이 대략 0.05초 정도 걸린다는 점으로부터 역산하면
	 * 0.05 * (N / 2^14) * r * p = 0.05 * 2^(M-11) * r * p < 600이어야 하므로
	 * 2^M * r * p < 600 / 0.05 * 2^11 < 2^25면 대강 1분 안에 나올 것이다. */
	if (M >= 25 || (r >> 25) != 0 || (p >> 25) != 0 || (((int64_t)r * p) >> (25 - M)) != 0) return 0;

	/* ------------------------------------------------------------ */
	*outN = (uint64_t)8 << (uint64_t)M;
	*outr = r;
	*outp = p;
	return cost & 0xffffff00;
}

static int walrus_stretch(byte_t *out, size_t outlen, const byte_t *k, size_t klen, const byte_t *s, size_t slen, walrus_stretch_cost cost, int require_safe)
{
	uint64_t N;
	uint32_t r;
	uint32_t p;

	assert(out != NULL);
	assert(k != NULL);
	assert(s != NULL);

	if (outlen <= WALRUS_STRETCH_COST_RAWLEN) return 0;
	cost = walrus_stretch_cost_check(cost, require_safe, &N, &r, &p);
	if (cost == 0) return 0;
	walrus_write_u32(out, cost);
	if (crypto_scrypt(k, klen, s, slen, N, r, p, out + WALRUS_STRETCH_COST_RAWLEN, outlen - WALRUS_STRETCH_COST_RAWLEN) != 0) return 0;
	return 1;
}

#ifdef TEST
static int walrus_stretch_run_tests(void)
{
	enum { BUFLEN = 1024 };

	byte_t a[BUFLEN];
	byte_t b[BUFLEN];
	walrus_stretch_cost cost;

	CHECK(WALRUS_STRETCH_RAWLEN < BUFLEN);

	PREPARE_BUF(a);
	PREPARE_BUF(b);
	CHECK(walrus_stretch(a, WALRUS_STRETCH_RAWLEN, "hello", 5, "world", 5, WALRUS_DEFAULT_STRETCH_COST, 1));
	CHECK(walrus_stretch(b, WALRUS_STRETCH_RAWLEN, "hello", 5, "world", 5, WALRUS_DEFAULT_STRETCH_COST, 1));
	CHECK_EQ(memcmp(a, b, WALRUS_STRETCH_RAWLEN), 0);
	CHECK_BUF(a, WALRUS_STRETCH_RAWLEN);
	CHECK_BUF(b, WALRUS_STRETCH_RAWLEN);
	CHECK_EQ(walrus_read_stretch_cost(a), WALRUS_DEFAULT_STRETCH_COST);

	CHECK(walrus_stretch(b, WALRUS_STRETCH_RAWLEN, "hello", 5, "earth", 5, WALRUS_DEFAULT_STRETCH_COST, 1));
	CHECK(memcmp(a, b, WALRUS_STRETCH_RAWLEN) != 0);
	CHECK(walrus_stretch(b, WALRUS_STRETCH_RAWLEN, "goodbye", 7, "world", 5, WALRUS_DEFAULT_STRETCH_COST, 1));
	CHECK(memcmp(a, b, WALRUS_STRETCH_RAWLEN) != 0);

	CHECK(walrus_stretch(b, 128, "hello", 5, "world", 5, WALRUS_DEFAULT_STRETCH_COST, 1));
	CHECK_EQ(memcmp(a, b, WALRUS_STRETCH_RAWLEN), 0);
	CHECK(walrus_stretch(a, 1024, "hello", 5, "world", 5, WALRUS_DEFAULT_STRETCH_COST, 1));
	CHECK_EQ(memcmp(a, b, 128), 0);
	
	cost = WALRUS_STRETCH_COST(11, 8, 1);
	CHECK(walrus_stretch(b, WALRUS_STRETCH_RAWLEN, "hello", 5, "world", 5, cost, 1));
	CHECK(memcmp(a, b, WALRUS_STRETCH_RAWLEN) != 0);
	CHECK_EQ(walrus_read_stretch_cost(b), cost);
	
	CHECK(!walrus_stretch(b, 0, "hello", 5, "world", 5, cost, 1));
	CHECK(!walrus_stretch(b, 1, "hello", 5, "world", 5, cost, 1));
	CHECK(!walrus_stretch(b, 2, "hello", 5, "world", 5, cost, 1));
	CHECK(!walrus_stretch(b, 3, "hello", 5, "world", 5, cost, 1));
	CHECK(walrus_stretch(b, 4, "hello", 5, "world", 5, cost, 1));

	/* 너무 낮은 파라미터는 기존 데이터와 비교하기 위해 require_safe = 0일 때만 허용한다 */
	cost = WALRUS_STRETCH_COST(3, 8, 1);
	CHECK(!walrus_stretch(b, WALRUS_STRETCH_RAWLEN, "hello", 5, "world", 5, cost, 1));
	CHECK(walrus_stretch(b, WALRUS_STRETCH_RAWLEN, "hello", 5, "world", 5, cost, 0));

	/* 너무 높은 파라미터는 그냥 죽인다 (곧이 곧대로 계산하면 메모리 16 GB를 쓰게 된다...) */
	cost = WALRUS_STRETCH_COST(20, 16, 1);
	CHECK(!walrus_stretch(b, WALRUS_STRETCH_RAWLEN, "hello", 5, "world", 5, cost, 1));
	CHECK(!walrus_stretch(b, WALRUS_STRETCH_RAWLEN, "hello", 5, "world", 5, cost, 0));

	/* 이상한 파라미터는 거절 */
	CHECK(!walrus_stretch(b, WALRUS_STRETCH_RAWLEN, "hello", 5, "world", 5, 0x12345678, 1));

	return 1;
}
#endif /* TEST */

/******************************************************************************/
/* secret 관리 */

#define WALRUS_SECRET_MAGIC 0xecfc375b

struct walrus_secret {
	uint32_t magic;
	walrus_stretch_cost currentcost;
	byte_t *salt;
	size_t saltlen;
	byte_t *decryptedsecret;
	size_t decryptedsecretlen;
	byte_t pkc[crypto_box_PUBLICKEYBYTES];
	byte_t sks[crypto_box_SECRETKEYBYTES];
	byte_t rawdummysecret[WALRUS_STRETCH_BUFLEN];
};

/* 암호화된 secret 포맷(base64 이후):
 * - 0..5: 고정된 바이트 59 A9 6B BA C4 B5 (base64로 인코딩했을 때 "WalrusS1")
 * - 6..37: byte_t[32] 서버측 공개키
 * - 38..69: byte_t[32] 클라이언트측 공개키
 * - 70..93: byte_t[24] nonce
 * - 94..109+x: byte_t[16+x] 암호화된 해시
 *
 * 일반적으로 x는 64바이트(HMAC-SHA512 해시)이나 C 인터페이스에서는 구분하지 않는다.
 * 따라서 총 메시지는 base64 이전 174바이트, base64 이후 235바이트이다.
 * 포맷의 제한 사항은 아니지만, 편의상 user 및 복호화된 해시는 64KB를 넘을 수 없다.
 */

#define WALRUS_SECRET_MAGIC_LEN 6
#define WALRUS_SECRET_PKS_OFFSET WALRUS_SECRET_MAGIC_LEN
#define WALRUS_SECRET_PKC_OFFSET (WALRUS_SECRET_PKS_OFFSET + crypto_box_PUBLICKEYBYTES)
#define WALRUS_SECRET_NONCE_OFFSET (WALRUS_SECRET_PKC_OFFSET + crypto_box_PUBLICKEYBYTES)
#define WALRUS_SECRET_MSG_OFFSET (WALRUS_SECRET_NONCE_OFFSET + crypto_box_NONCEBYTES)
#define WALRUS_SECRET_RAWOVERHEAD (WALRUS_SECRET_MSG_OFFSET + crypto_box_MACBYTES)

/* 암호화된 result 포맷 (base64 이후):
 * - 0..5: 고정된 바이트 59 A9 6B BA C4 75 (base64로 인코딩했을 때 "WalrusR1")
 * - 6..29: byte_t[24] nonce
 * - 30..45+x: byte_t[16+x] 암호화된 결과물
 */

#define WALRUS_RESULT_MAGIC_LEN 6
#define WALRUS_RESULT_NONCE_OFFSET WALRUS_RESULT_MAGIC_LEN
#define WALRUS_RESULT_OUTPUT_OFFSET (WALRUS_RESULT_NONCE_OFFSET + crypto_box_NONCEBYTES)
#define WALRUS_RESULT_RAWOVERHEAD (WALRUS_RESULT_OUTPUT_OFFSET + crypto_box_MACBYTES)

#define WALRUS_SERVER_SALT_PREFIX_LEN 16

static const byte_t WALRUS_SECRET_B64_MAGIC[WALRUS_B64_ENCODE_OUTLEN(WALRUS_SECRET_MAGIC_LEN)] = "WalrusS1";
static const byte_t WALRUS_RESULT_MAGIC[WALRUS_RESULT_MAGIC_LEN] = { 0x59, 0xa9, 0x6b, 0xb4, 0xc4, 0x75 };
static const byte_t WALRUS_SERVER_SALT_PREFIX[WALRUS_SERVER_SALT_PREFIX_LEN] = "SilvervineServer";

static int walrus_secret_valid_magic(const walrus_secret *ws)
{
	return ws != NULL && ws->magic == WALRUS_SECRET_MAGIC;
}

static int walrus_secret_init(
	walrus_secret *ws,
	const walrus_keypair *keypairs, size_t nkeypairs,
	const byte_t *realm, size_t realmlen,
	const char *user, size_t userlen,
	const char *secret, size_t secretlen)
{
	byte_t *rawsecret;
	size_t rawsecretlen;
	size_t i;
	int ret;

	assert(ws != NULL);
	assert(realm != NULL);
	assert(user != NULL);
	assert(secret != NULL);

	if (keypairs == NULL || nkeypairs == 0) goto error;

	/* 암호화 전의 secret이 빈 문자열일 경우도 오류로 처리함 */
	if (secretlen <= WALRUS_SECRET_RAWOVERHEAD) goto error;
	if (memcmp(secret, WALRUS_SECRET_B64_MAGIC, 8) != 0) goto error;

	/* 입력이 너무 클 경우에도 오류. DoS를 방지한다. */
	if (userlen > 64 * 1024) goto error;
	if (secretlen > WALRUS_B64_ENCODE_OUTLEN(WALRUS_SECRET_RAWOVERHEAD + 64 * 1024)) goto error;

	rawsecret = malloc(WALRUS_B64_DECODE_OUTLEN_MAX(secretlen));
	if (rawsecret == NULL) goto error;
	rawsecretlen = walrus_b64_decode(rawsecret, secret, secretlen);
	if (rawsecretlen == (size_t)(-1)) goto free_rawsecret;

	/* 맞는 비밀키를 찾아 낸다 */
	for (i = 0; i < nkeypairs; ++i) {
		if (memcmp(keypairs[i].pk, rawsecret + WALRUS_SECRET_PKS_OFFSET, crypto_box_PUBLICKEYBYTES) == 0) {
			memcpy(ws->pkc, rawsecret + WALRUS_SECRET_PKC_OFFSET, crypto_box_PUBLICKEYBYTES);
			memcpy(ws->sks, keypairs[i].sk, crypto_box_SECRETKEYBYTES);
			goto found_key;
		}
	}
	goto free_rawsecret;

found_key:
	ws->decryptedsecretlen = rawsecretlen - WALRUS_SECRET_RAWOVERHEAD;
	ws->decryptedsecret = malloc(ws->decryptedsecretlen);
	if (ws->decryptedsecret == NULL) goto free_rawsecret;

	ret = crypto_box_easy_open(
		ws->decryptedsecret,
		rawsecret + WALRUS_SECRET_MSG_OFFSET, rawsecretlen - WALRUS_SECRET_MSG_OFFSET,
		rawsecret + WALRUS_SECRET_NONCE_OFFSET,
		ws->pkc, ws->sks);
	if (ret != 0) goto free_decryptedsecret;

	/* salt를 초기화한다 (따라서 realm과 user를 빌리지 않는다) */
	ws->saltlen = WALRUS_SERVER_SALT_PREFIX_LEN + realmlen + userlen;
	ws->salt = malloc(ws->saltlen);
	if (ws->salt == NULL) goto free_decryptedsecret;
	memcpy(ws->salt, WALRUS_SERVER_SALT_PREFIX, WALRUS_SERVER_SALT_PREFIX_LEN);
	memcpy(ws->salt + WALRUS_SERVER_SALT_PREFIX_LEN, realm, realmlen);
	memcpy(ws->salt + WALRUS_SERVER_SALT_PREFIX_LEN + realmlen, user, userlen);

	ws->magic = WALRUS_SECRET_MAGIC;
	free(rawsecret);
	return 1;

free_decryptedsecret:
	free(ws->decryptedsecret);
free_rawsecret:
	free(rawsecret);
error:
	return 0;
}

void walrus_free_secret(walrus_secret *ws)
{
	if (ws != NULL) {
		assert(walrus_secret_valid_magic(ws));
		free(ws->decryptedsecret);
		free(ws->salt);
		ws->decryptedsecret = NULL;
		ws->salt = NULL;
		free(ws);
	}
}

void walrus_free_secret_str(walrus_secret *ws, char *buf)
{
	assert(walrus_secret_valid_magic(ws));
	free(buf);
}

enum walrus_verify walrus_verify_secret(const walrus_secret *ws, const char *stored, size_t len)
{
	byte_t prevstretched[WALRUS_STRETCH_BUFLEN];
	byte_t stretched[WALRUS_STRETCH_BUFLEN];
	walrus_stretch_cost cost;
	size_t i;
	byte_t acc;

	if (!walrus_secret_valid_magic(ws)) return WALRUS_VERIFY_BAD;

	if (stored == NULL) {
		stored = ws->rawdummysecret;
	} else if (len != WALRUS_STRETCH_LEN) {
		return WALRUS_VERIFY_BAD;
	}

	if (walrus_b64_decode(prevstretched, stored, WALRUS_STRETCH_LEN) != WALRUS_STRETCH_RAWLEN) {
		return WALRUS_VERIFY_BAD;
	}
	cost = walrus_read_stretch_cost(prevstretched);
	if (!walrus_stretch(stretched, WALRUS_STRETCH_RAWLEN, ws->decryptedsecret, ws->decryptedsecretlen, ws->salt, ws->saltlen, cost, 0)) {
		return WALRUS_VERIFY_BAD;
	}

	/* 상수 시간 비교로 타이밍 공격을 막는다 (crypto_verify* 등은 길이가 고정이라...) */
	acc = 0;
	for (i = 0; i < WALRUS_STRETCH_RAWLEN; ++i) {
		acc |= stretched[i] ^ prevstretched[i];
	}
	if (acc != 0) return WALRUS_VERIFY_BAD;

	return (cost == ws->currentcost ? WALRUS_VERIFY_OK : WALRUS_VERIFY_OK_BUT_REEXPORT_NEEDED);
}

char *walrus_export_secret(const walrus_secret *ws, size_t *buflen)
{
	byte_t stretched[WALRUS_STRETCH_BUFLEN];

	if (!walrus_secret_valid_magic(ws)) return NULL;

	if (!walrus_stretch(stretched, WALRUS_STRETCH_RAWLEN, ws->decryptedsecret, ws->decryptedsecretlen, ws->salt, ws->saltlen, ws->currentcost, 1)) {
		return NULL;
	}

	return walrus_b64_encode_alloc(stretched, WALRUS_STRETCH_RAWLEN, buflen);
}

char *walrus_make_result(const walrus_secret *ws, const char *result, size_t resultlen, size_t *buflen)
{
	byte_t *rawbuf;
	size_t rawbuflen;
	char *out;
	int ret;

	if (!walrus_secret_valid_magic(ws)) goto error;
	
	rawbuflen = resultlen + WALRUS_RESULT_RAWOVERHEAD;

	rawbuf = malloc(rawbuflen);
	if (rawbuf == NULL) goto error;

	memcpy(rawbuf, WALRUS_RESULT_MAGIC, WALRUS_RESULT_MAGIC_LEN);
	randombytes(rawbuf + WALRUS_RESULT_NONCE_OFFSET, crypto_box_NONCEBYTES);
	ret = crypto_box_easy(
		rawbuf + WALRUS_RESULT_OUTPUT_OFFSET,
		result, resultlen,
		rawbuf + WALRUS_RESULT_NONCE_OFFSET,
		ws->pkc, ws->sks);
	if (ret != 0) goto free_rawbuf;

	out = walrus_b64_encode_alloc(rawbuf, rawbuflen, buflen);
	free(rawbuf);
	return out;

free_rawbuf:
	free(rawbuf);
error:
	return NULL;
}

#ifdef TEST
static int walrus_secret_run_tests(void)
{
	return 1;
}
#endif /* TEST */

/******************************************************************************/

#define WALRUS_MAGIC 0xaf53740c

struct walrus {
	uint32_t magic;
	char *realm;
	size_t realmlen;
	walrus_keypair *keypairs; /* created 순서대로 정렬 */
	size_t nkeypairs;
	unsigned int rehashintervalsec;
	walrus_stretch_cost currentcost;
	byte_t rawdummysecret[WALRUS_STRETCH_BUFLEN];
};

#define WALRUS_DEFAULT_REHASH_INTERVAL_SEC (60 * 10)

static int walrus_valid_magic(const walrus *w)
{
	return w != NULL && w->magic == WALRUS_MAGIC;
}

walrus *walrus_new(const char *realm, size_t len)
{
	walrus *w;

	/* 파라미터 포맷에서 realm 길이를 32비트로 제한하기 때문에 이를 넘으면 인코딩 자체가 불가능하다 */
	if (((len >> 16) >> 16) != 0) return NULL;

	w = malloc(sizeof(walrus));
	if (w == NULL) goto error;
	w->magic = WALRUS_MAGIC;
	w->realm = malloc(len);
	if (w->realm == NULL) goto free_walrus;
	w->realmlen = len;
	w->keypairs = NULL;
	w->nkeypairs = 0;
	w->rehashintervalsec = WALRUS_DEFAULT_REHASH_INTERVAL_SEC;
	w->currentcost = WALRUS_DEFAULT_STRETCH_COST;

	/* dummy secret이란 사용자가 없다는 것을 숨기기 위해 사용하는 가짜 값이다.
	 * 이 녀석의 정체는 헤더만 멀쩡하고 나머지는 완전한 랜덤값. */
	walrus_write_u32(w->rawdummysecret, w->currentcost);
	randombytes(w->rawdummysecret + WALRUS_STRETCH_COST_RAWLEN, WALRUS_STRETCH_HASH_RAWLEN);

	return w;

free_walrus:
	free(w);
error:
	return NULL;
}

void walrus_free(walrus *w)
{
	if (w != NULL) {
		assert(walrus_valid_magic(w));
		free(w->realm);
		free(w->keypairs);
		w->realm = NULL;
		w->keypairs = NULL;
		free(w);
	}
}

void walrus_free_str(walrus *w, char *buf)
{
	assert(walrus_valid_magic(w));
	free(buf);
}

unsigned int walrus_set_rehash_interval(walrus *w, unsigned int intervalsec)
{
	if (!walrus_valid_magic(w)) return 0;

	if (intervalsec == 0) intervalsec = WALRUS_DEFAULT_REHASH_INTERVAL_SEC;
	w->rehashintervalsec = intervalsec;
	return intervalsec;
}

unsigned int walrus_set_stretch_cost(walrus *w, unsigned int cost0)
{
	walrus_stretch_cost cost;
	uint64_t N;
	uint32_t r;
	uint32_t p;

	if (!walrus_valid_magic(w)) return 0;

	/* unsigned int가 32비트보다 작은 경우 이 API는 의미가 없다. 이런 플랫폼에서는 그냥 동작을 막는다.
	 * (초기화는 이 코드를 타지 않으므로 이 API를 사용하지 않는다면 문제는 없다.) */
	if (sizeof(unsigned int) < sizeof(uint32_t)) return 0;

	if (cost0 == 0) {
		cost = WALRUS_DEFAULT_STRETCH_COST;
	} else {
		cost = walrus_stretch_cost_check((uint32_t)cost0, 1, &N, &r, &p);
		if (cost == 0) return 0;
	}

	/* cost가 바뀌었으니 rawdummysecret을 갱신한다. */
	w->currentcost = cost;
	walrus_write_u32(w->rawdummysecret, w->currentcost);
	randombytes(w->rawdummysecret + WALRUS_STRETCH_COST_RAWLEN, WALRUS_STRETCH_HASH_RAWLEN);

	return (unsigned int)cost;
}

enum walrus_rehash walrus_rehash(walrus *w, const time_t *nowptr)
{
	time_t now;
	int64_t keepafter;
	int64_t freshafter;
	size_t i;
	size_t offset;
	size_t prevnkeypairs;
	int fresh;

	if (!walrus_valid_magic(w)) return WALRUS_REHASH_FAILED;

	now = nowptr ? *nowptr : time(NULL);

	/* 1. 너무 오래된(현재 시각으로부터 2 * interval 이상 지난) 파라미터는 삭제한다.
	 * 2. 가장 새로운 파라미터가 interval 이상의 시간이 지났으면 새 파라미터를 만든다. */
	keepafter = (int64_t)now - (int64_t)w->rehashintervalsec * 2;
	freshafter = (int64_t)now - (int64_t)w->rehashintervalsec;

	/* 제자리에서 w->keypairs를 갱신한다 */
	fresh = 0;
	offset = 0;
	for (i = 0; i < w->nkeypairs; ++i) {
		if (w->keypairs[i].created >= keepafter) {
			fresh |= w->keypairs[i].created >= freshafter;
			w->keypairs[i - offset] = w->keypairs[i];
		} else {
			++offset;
		}
	}
	prevnkeypairs = w->nkeypairs;
	w->nkeypairs -= offset;

	if (fresh) {
		return WALRUS_REHASH_OK;
	} else {
		/* 새 키 쌍을 생성해야 한다. 필요하면 keypairs를 재할당한다. */
		if (prevnkeypairs == w->nkeypairs) {
			walrus_keypair *keypairs = realloc(w->keypairs, (w->nkeypairs + 1) * sizeof(walrus_keypair));
			if (keypairs == NULL) return WALRUS_REHASH_FAILED;
			w->keypairs = keypairs;
		}
		
		walrus_keypair_generate(&w->keypairs[w->nkeypairs++], now);
		return WALRUS_REHASH_PLEASE_EXPORT;
	}
}

int walrus_import_keypairs(walrus *w, const char *stored, size_t len)
{
	const char *end;
	walrus_keypair *keypairs;
	size_t nkeypairs;
	size_t i;
	const char *p;

	if (!walrus_valid_magic(w)) goto error;
	if (stored == NULL) goto error;
	if (len == 0) goto error;

	/* 포맷: <k1> "," <k2> "," ... <kn> "." (단, 비었을 경우 ".")
	 * <ki>는 walrus_keypair_write가 쓰는 base64 인코딩이다. */

	/* 위에서 알 수 있듯 마지막 문자가 "."가 아니면 오류 */
	end = stored + len - 1;
	if (*end != '.') goto error;

	/* 키가 아예 없는가? */
	nkeypairs = 0;
	if (len == 1) {
		keypairs = NULL;
		goto done;
	}

	/* "," 갯수를 센다 */
	nkeypairs = 1;
	for (p = stored; p < end; ++p) {
		if (*p == ',') ++nkeypairs;
	}

	keypairs = malloc(nkeypairs * sizeof(walrus_keypair));
	if (keypairs == NULL) goto error;

	i = 0;
	p = stored;
	while (p < end) {
		const char *partstart = p;
		const char *partend = memchr(p, ',', end - p);
		if (partend) {
			/* 다음 시작 지점은 *p(",") 다음 문자이다 */
			p = partend + 1;
		} else {
			partend = end;
			p = end;
		}

		if (!walrus_keypair_read(&keypairs[i++], partstart, partend - partstart)) {
			goto free_keypairs;
		}
	}

done:
	free(w->keypairs);
	w->keypairs = keypairs;
	w->nkeypairs = nkeypairs;
	return 1;

free_keypairs:
	free(keypairs);
error:
	return 0;
}

char *walrus_export_keypairs(const walrus *w, size_t *buflen)
{
	char *exported;
	char *p;
	size_t outlen;
	size_t i;

	if (!walrus_valid_magic(w)) return NULL;

	/* 키 쌍이 없을 경우 특수한 포맷을 쓴다 */
	if (w->nkeypairs == 0) {
		exported = malloc(2);
		if (exported == NULL) return NULL;
		exported[0] = '.';
		exported[1] = '\0';
		if (buflen != NULL) *buflen = 1;
		return exported;
	}

	/* 각 키 쌍마다 (WALRUS_KEYPAIR_LEN바이트 + 구분자 1바이트) + 널 문자 1바이트 */
	outlen = w->nkeypairs * (WALRUS_KEYPAIR_LEN + 1);
	exported = malloc(outlen + 1);
	if (exported == NULL) return NULL;

	p = exported;
	for (i = 0; i < w->nkeypairs; ++i) {
		walrus_keypair_write(&w->keypairs[i], p);
		p[WALRUS_KEYPAIR_LEN] = (i + 1 < w->nkeypairs ? ',' : '.');
		p += WALRUS_KEYPAIR_LEN + 1;
	}
	*p = '\0';

	if (buflen != NULL) *buflen = outlen;
	return exported;
}

char *walrus_get_params(const walrus *w, size_t *buflen)
{
	byte_t *rawparams;
	size_t rawparamslen;
	char *params;

	/* 파라미터 포맷(base64 이후):
	 * - 0..5: 고정된 바이트 59 A9 6B BA C3 F5 (base64로 인코딩했을 때 "WalrusP1")
	 * - 6..37: byte_t[32] 서버측 공개키
	 * - 38..41: uint32_t realm 길이
	 * - 42..: byte_t[*] realm
	 */

	#define WALRUS_PARAMS_PKS_OFFSET 6
	#define WALRUS_PARAMS_REALMLEN_OFFSET (WALRUS_PARAMS_PKS_OFFSET + crypto_box_PUBLICKEYBYTES)
	#define WALRUS_PARAMS_REALM_OFFSET (WALRUS_PARAMS_REALMLEN_OFFSET + 4)

	#define WALRUS_PARAMS_MAGIC_LEN 6

	static const byte_t WALRUS_PARAMS_MAGIC[WALRUS_PARAMS_MAGIC_LEN] = { 0x59, 0xa9, 0x6b, 0xba, 0xc3, 0xf5 };

	if (!walrus_valid_magic(w)) return NULL;
	if (w->nkeypairs == 0) return NULL;
	
	rawparamslen = WALRUS_PARAMS_REALM_OFFSET + w->realmlen;
	rawparams = malloc(rawparamslen);
	if (rawparams == NULL) return NULL;
	
	memcpy(rawparams, WALRUS_PARAMS_MAGIC, WALRUS_PARAMS_MAGIC_LEN);
	memcpy(rawparams + WALRUS_PARAMS_PKS_OFFSET, w->keypairs[w->nkeypairs - 1].pk, crypto_box_PUBLICKEYBYTES);
	walrus_write_u32(rawparams + WALRUS_PARAMS_REALMLEN_OFFSET, (uint32_t)w->realmlen);
	memcpy(rawparams + WALRUS_PARAMS_REALM_OFFSET, w->realm, w->realmlen);

	params = walrus_b64_encode_alloc(rawparams, rawparamslen, buflen);
	free(rawparams);
	return params;
}

walrus_secret *walrus_decode_secret(const walrus *w, const char *user, size_t userlen, const char *secret, size_t secretlen)
{
	walrus_secret *ws;

	if (!walrus_valid_magic(w)) return NULL;

	ws = malloc(sizeof(walrus_secret));
	if (ws == NULL) return NULL;

	if (!walrus_secret_init(ws, w->keypairs, w->nkeypairs, w->realm, w->realmlen, user, userlen, secret, secretlen)) {
		free(ws);
		return NULL;
	}

	/* walrus가 사라져도 walrus_secret이 보존될 수 있도록 currentcost와 rawdummysecret도 복사한다. */
	ws->currentcost = w->currentcost;
	memcpy(ws->rawdummysecret, w->rawdummysecret, WALRUS_STRETCH_RAWLEN);

	return ws;
}

#ifdef TEST
static int walrus_core_run_tests(void)
{
	walrus *w;
	time_t now;
	char *keypairs;
	char *keypairs2;
	size_t keypairslen;

	w = walrus_new("realm", 5);
	CHECK(w != NULL);

	now = 1000000000;
	CHECK_EQ(walrus_rehash(w, &now), WALRUS_REHASH_PLEASE_EXPORT);
	CHECK_EQ(walrus_rehash(w, &now), WALRUS_REHASH_OK);
	now += 10;
	CHECK_EQ(walrus_rehash(w, &now), WALRUS_REHASH_OK);
	now += WALRUS_DEFAULT_REHASH_INTERVAL_SEC;
	CHECK_EQ(walrus_rehash(w, &now), WALRUS_REHASH_PLEASE_EXPORT);

	keypairs = walrus_export_keypairs(w, &keypairslen);
	CHECK(keypairs != NULL);
	CHECK_EQ(keypairslen, strlen(keypairs));
	CHECK(walrus_import_keypairs(w, keypairs, keypairslen));
	keypairs2 = walrus_export_keypairs(w, &keypairslen);
	CHECK(keypairs2 != NULL);
	CHECK_EQ(keypairslen, strlen(keypairs2));
	CHECK_EQ(strcmp(keypairs, keypairs2), 0);
	free(keypairs);
	free(keypairs2);

	return 1;
}
#endif /* TEST */

/******************************************************************************/

int walrus_run_tests(void)
{
#ifdef TEST
	randombytes(walrus_random_buf, sizeof(walrus_random_buf));

	#define RUN_TEST(f) do { fprintf(stderr, "%s... ", #f); if (f()) fprintf(stderr, "done.\n"); } while (0)
	RUN_TEST(walrus_b64_run_tests);
	RUN_TEST(walrus_keypair_run_tests);
	RUN_TEST(walrus_stretch_run_tests);
	RUN_TEST(walrus_secret_run_tests);
	RUN_TEST(walrus_core_run_tests);
	return 1;
#else
	/* 매크로가 설정되어 있지 않더라도 이 함수 자체는 빈 채로 놔둔다. */
	return 0;
#endif
}
