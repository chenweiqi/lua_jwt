/* Lua jwt - a jwt library for Lua
 *
 * Copyright (c) 2020  chenweiqi
 *
 * The MIT License (MIT)
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>
#include <lua.h>
#include <lauxlib.h>
#include <setjmp.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "jwt.h"

#define LJWT_ESZ 20

typedef struct LJWT_ALG {
  const char *name;
  jwt_alg_t alg;
} LJWT_ALG;


const LJWT_ALG ljwt_algs[] = {
	{"hs256", JWT_ALG_HS256},
	{"rs256", JWT_ALG_RS256},
	{"es256", JWT_ALG_ES256},
	{NULL}
};


#define TRY_BEGIN do {	\
	jmp_buf __try_b;	\
	char __try_m[LJWT_ESZ+1] = {0};
#define Try if (setjmp(__try_b) == 0)
#define Catch(err) else if ((err = __try_m)) 
#define Throw(err) { \
	snprintf(__try_m, LJWT_ESZ, "%s", err);	\
	longjmp(__try_b, 1);	\
}
#define Finally
#define TRY_END } while(0);

/**
 * jwt_encode
 */
static int ljwt_encode(lua_State *L)
{
	jwt_t *jwt = NULL;
	char *jwt_str = NULL;
	jwt_alg_t alg = JWT_ALG_NONE;
	const LJWT_ALG *alg_p = ljwt_algs;
	int ret;
	char* errmsg;

	TRY_BEGIN
	Try {
		size_t pem_sz = 0;
		const unsigned char *pem_str = (const unsigned char *)luaL_checklstring(L, 3, &pem_sz);
		size_t alg_sz = 0;
		const char * alg_str = luaL_checklstring(L, 4, &alg_sz);
		luaL_checktype(L, 1, LUA_TTABLE);
		luaL_checktype(L, 2, LUA_TTABLE);

		for (; alg_p->name; alg_p++) {
			if (strcmp(alg_p->name, alg_str) == 0) {
				alg = alg_p->alg;
				break;
			}
		}

		ret = jwt_new(&jwt);
		if (ret != 0) Throw("jwt_new");

		lua_pushnil(L);
		while (lua_next(L, 1))
		{
			switch (lua_type(L, -1))
			{
				case LUA_TSTRING:
					ret = jwt_add_header(jwt, lua_tostring(L, -2), lua_tostring(L, -1));
					break;
				case LUA_TNUMBER:
					ret = jwt_add_header_int(jwt, lua_tostring(L, -2), lua_tonumber(L, -1));
					break;
				case LUA_TBOOLEAN:
					ret = jwt_add_header_bool(jwt, lua_tostring(L, -2), lua_toboolean(L, -1));
					break;
				default:
					ret = !0;
			}
			if (ret != 0) Throw("jwt_add_header");
			lua_pop(L, 1);
		}

		lua_pushnil(L);
		while (lua_next(L, 2))
		{
			switch (lua_type(L, -1))
			{
				case LUA_TSTRING:
					ret = jwt_add_grant(jwt, lua_tostring(L, -2), lua_tostring(L, -1));
					break;
				case LUA_TNUMBER:
					ret = jwt_add_grant_int(jwt, lua_tostring(L, -2), lua_tonumber(L, -1));
					break;
				case LUA_TBOOLEAN:
					ret = jwt_add_grant_bool(jwt, lua_tostring(L, -2), lua_toboolean(L, -1));
					break;
				default:
					ret = !0;
			}
			if (ret != 0) Throw("jwt_add_grant");

			lua_pop(L, 1);
		}

		ret = jwt_set_alg(jwt, alg, pem_str, pem_sz);
		if (ret != 0) Throw("jwt_set_alg");

		jwt_str = jwt_encode_str(jwt);
		if (jwt_str == NULL) Throw("jwt_encode_str");

		lua_pushboolean(L, 1);
		lua_pushlstring(L, jwt_str, strlen(jwt_str));

	} Catch (errmsg) {
		lua_pushboolean(L, 0);
		lua_pushlstring(L, errmsg, strlen(errmsg));
	}
	TRY_END

	if (jwt_str != NULL)
		jwt_free_str(jwt_str);
	if (jwt != NULL)
		jwt_free(jwt);
	return 2;
}

/**
 * jwt_decode
 */
static int ljwt_decode(lua_State *L)
{
	jwt_t *jwt = NULL;
	char* token_str = NULL;
	int ret;
	char* errmsg;

	size_t jwt_sz = 0;
	size_t pem_sz = 0;
	const char * jwt_str = NULL;
	const unsigned char * pem_str = NULL;
	int top = lua_gettop(L);

	TRY_BEGIN
	Try {
		jwt_str = luaL_checklstring(L, 1, &jwt_sz);
		if ( top > 1 )
			pem_str = (const unsigned char *)luaL_checklstring(L, 2, &pem_sz);

		ret = jwt_decode(&jwt, jwt_str, pem_str, pem_sz);
		if (ret != 0) Throw("jwt_decode");

		token_str = jwt_dump_str(jwt, 0);
		if (token_str == NULL) Throw("jwt_dump_str");

		lua_pushboolean(L, 1);
		lua_pushlstring(L, token_str, strlen(token_str));
	} Catch (errmsg) {
		lua_pushboolean(L, 0);
		lua_pushlstring(L, errmsg, strlen(errmsg));
	}
	TRY_END

	if (token_str != NULL)
		jwt_free_str(token_str);
	if (jwt != NULL)
		jwt_free(jwt);
	return 2;
}


void base64_decode(const char* input, int length, unsigned char** out, int* out_sz)
{
	BIO *b64 = NULL, *bio = NULL;
	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bio = BIO_new_mem_buf(input, length);
	bio = BIO_push(b64, bio);
	*out_sz = BIO_read(bio, *out, length);
	BIO_free_all(bio);
}

void base64url_decode(const char* input, int len, unsigned char** out, int* out_sz)
{
	size_t pad;
	int i;
	char *burl = NULL;

	pad = len + ( 4 - len % 4) % 4;
	burl = (char *)malloc(pad + 1);
	if (burl == NULL) return;
	memset(burl, 0, pad + 1);
	memcpy(burl, input, len);

	for (i = 0; i < len; i++) {
		if ('-' == *(burl+i))
			*(burl+i) = '+';
		else if ('_' == *(burl+i))
			*(burl+i) = '/';
	}
	for (i = 0; i < (pad - len); i++) {
		burl[len + i] = '=';
	}
	base64_decode(burl, pad, out, out_sz);
	free (burl);
}


void bin2hex(const unsigned char *bin, int len, char **out) {
  	static const char hex[] = "0123456789abcdef";
	char *p = *out;
	for (; len--; bin++) {
		*p++ = hex[bin[0] >> 4];
		*p++ = hex[bin[0] & 0x0f];
	}
	*p = '\0';
}

char * jwk_key_decode(const char *key, int key_sz)
{
	unsigned char *int_bin;
	int int_bin_sz = 0;
	char *key_hex = NULL;

	int_bin = (unsigned char *)malloc(key_sz);
	if (int_bin == NULL) return NULL;
	memset(int_bin, 0, key_sz);

	base64url_decode(key, key_sz, &int_bin, &int_bin_sz);
	if (int_bin_sz > 0) {
		key_hex = (char *)malloc(int_bin_sz*2 +1);
		if (key_hex != NULL) {
			memset(key_hex, 0, int_bin_sz*2 +1);
			bin2hex(int_bin, int_bin_sz, &key_hex);
		}
	}
	free(int_bin);
	return key_hex;
}

/**
 * jwk_to_pem
 */
static int ljwk_to_pem(lua_State *L)
{
	RSA *rsa = NULL;
	BIGNUM *bne = NULL, *bnm = NULL;
	char *modulus = NULL, *exponent = NULL;
	EVP_PKEY* pkey = NULL;
	BIO *bio = NULL;
	char *pem_str = NULL;
	int pem_sz;
	int ret;
	char* errmsg;


	TRY_BEGIN
	Try {
		size_t modulus_sz = 0;
		size_t exponent_sz = 0;
		const char * modulus_str = luaL_checklstring(L, 1, &modulus_sz);
		const char * exponent_str = luaL_checklstring(L, 2, &exponent_sz);
		if (modulus_sz == 0) Throw("modulus invalid");
		if (exponent_sz == 0) Throw("exponent invalid");

		modulus = jwk_key_decode(modulus_str, modulus_sz);
		if (modulus == NULL) Throw("modulus decode");
		exponent = jwk_key_decode(exponent_str, exponent_sz);
		if (exponent == NULL) Throw("exponent decode");

		ret = BN_hex2bn(&bnm, modulus);
		if (ret == 0) Throw("modulus hex2bn");
		ret = BN_hex2bn(&bne, exponent);
		if (ret == 0) Throw("exponent hex2bn");

		rsa = RSA_new();
		if (rsa == NULL) Throw("rsa new");
		rsa->n = bnm;
		rsa->e = bne;

		pkey = EVP_PKEY_new();
		if (pkey == NULL) Throw("pkey new");
		EVP_PKEY_set1_RSA(pkey, rsa);

		bio = BIO_new(BIO_s_mem()); 
		if (bio == NULL) Throw("bio new");
		PEM_write_bio_PUBKEY(bio, pkey);

		pem_sz = BIO_number_written(bio);
		pem_str = (char *) malloc(pem_sz + 1);
		if (pem_str == NULL) Throw("pem malloc");
		memset(pem_str, 0, pem_sz + 1);
		BIO_read(bio, pem_str, pem_sz + 1);

		lua_pushboolean(L, 1);
		lua_pushlstring(L, pem_str, pem_sz);
	} Catch (errmsg) {
		lua_pushboolean(L, 0);
		lua_pushlstring(L, errmsg, strlen(errmsg));
	}
	TRY_END

	if (pem_str != NULL)
		free(pem_str);
	if (bio != NULL)
		BIO_free_all(bio);
	if (pkey != NULL)
		EVP_PKEY_free(pkey);
	if (modulus != NULL)
		free(modulus);
	if (exponent != NULL)
		free(exponent);
	if (rsa != NULL)
		RSA_free(rsa);
	return 2;

}

int luaopen_jwt(lua_State *L)
{
	static const luaL_Reg funcs[] = {
		{"jwt_encode", ljwt_encode},
		{"jwt_decode", ljwt_decode},
		{"jwk_to_pem", ljwk_to_pem},
		{NULL, NULL}
	};
	luaL_newlib(L, funcs);
	return 1;
}

