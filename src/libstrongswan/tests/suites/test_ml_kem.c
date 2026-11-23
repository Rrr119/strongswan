/*
 * Copyright (C) 2026 Tobias Brunner
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "test_suite.h"

typedef struct ml_kem_test_t ml_kem_test_t;

struct ml_kem_test_t {
	key_exchange_method_t method;
	u_int pk_len;
	u_int ct_len;
};

/**
 * Parameter sets of ML-KEM (FIPS 203), the shared secret is 32 bytes for all
 * of them.
 */
static ml_kem_test_t ml_kem_tests[] = {
	{ ML_KEM_512,   800,  768 },
	{ ML_KEM_768,  1184, 1088 },
	{ ML_KEM_1024, 1568, 1568 },
};

#define ML_KEM_SS_LEN	32

START_TEST(test_encaps_decaps)
{
	key_exchange_t *initiator, *responder;
	chunk_t pk, ct, ss_i, ss_r;

	initiator = lib->crypto->create_ke(lib->crypto,
									   ml_kem_tests[_i].method);
	ck_assert(initiator);
	responder = lib->crypto->create_ke(lib->crypto,
									   ml_kem_tests[_i].method);
	ck_assert(responder);

	/* the initiator generates a key pair and sends the encapsulation key */
	ck_assert(initiator->get_public_key(initiator, &pk));
	ck_assert_int_eq(pk.len, ml_kem_tests[_i].pk_len);

	/* the responder encapsulates a shared secret with that key */
	ck_assert(responder->set_public_key(responder, pk));
	ck_assert(responder->get_public_key(responder, &ct));
	ck_assert_int_eq(ct.len, ml_kem_tests[_i].ct_len);

	/* the initiator decapsulates the secret from the ciphertext */
	ck_assert(initiator->set_public_key(initiator, ct));

	ck_assert(initiator->get_shared_secret(initiator, &ss_i));
	ck_assert(responder->get_shared_secret(responder, &ss_r));
	ck_assert_int_eq(ss_i.len, ML_KEM_SS_LEN);
	ck_assert_int_eq(ss_r.len, ML_KEM_SS_LEN);
	ck_assert_chunk_eq(ss_i, ss_r);

	chunk_free(&pk);
	chunk_free(&ct);
	chunk_free(&ss_i);
	chunk_free(&ss_r);
	initiator->destroy(initiator);
	responder->destroy(responder);
}
END_TEST

START_TEST(test_invalid_public_key)
{
	key_exchange_t *responder;
	chunk_t pk;

	responder = lib->crypto->create_ke(lib->crypto,
									   ml_kem_tests[_i].method);
	ck_assert(responder);

	/* a public key of the wrong size has to be rejected */
	pk = chunk_alloc(ml_kem_tests[_i].pk_len - 1);
	memset(pk.ptr, 0xa5, pk.len);
	ck_assert(!responder->set_public_key(responder, pk));
	chunk_free(&pk);

	/* a non-canonical encoding (coefficients >= q) fails the modulus check
	 * required by section 7.2 of FIPS 203 */
	pk = chunk_alloc(ml_kem_tests[_i].pk_len);
	memset(pk.ptr, 0xff, pk.len);
	ck_assert(!responder->set_public_key(responder, pk));
	chunk_free(&pk);

	/* no shared secret may be available after failed encapsulation */
	ck_assert(!responder->get_shared_secret(responder, &pk));

	responder->destroy(responder);
}
END_TEST

START_TEST(test_invalid_ciphertext)
{
	key_exchange_t *initiator, *responder;
	chunk_t pk, ct, ss_i, ss_r;

	initiator = lib->crypto->create_ke(lib->crypto,
									   ml_kem_tests[_i].method);
	ck_assert(initiator);
	responder = lib->crypto->create_ke(lib->crypto,
									   ml_kem_tests[_i].method);
	ck_assert(responder);

	ck_assert(initiator->get_public_key(initiator, &pk));
	ck_assert(responder->set_public_key(responder, pk));
	ck_assert(responder->get_public_key(responder, &ct));

	/* a ciphertext of the wrong size has to be rejected */
	ct.len--;
	ck_assert(!initiator->set_public_key(initiator, ct));
	ct.len++;

	/* a modified ciphertext is implicitly rejected (FIPS 203, algorithm 18),
	 * so decapsulation succeeds but the shared secrets don't match */
	ct.ptr[0] ^= 0x01;
	ck_assert(initiator->set_public_key(initiator, ct));

	ck_assert(initiator->get_shared_secret(initiator, &ss_i));
	ck_assert(responder->get_shared_secret(responder, &ss_r));
	ck_assert_int_eq(ss_i.len, ML_KEM_SS_LEN);
	ck_assert_int_eq(ss_r.len, ML_KEM_SS_LEN);
	ck_assert(!chunk_equals(ss_i, ss_r));

	chunk_free(&pk);
	chunk_free(&ct);
	chunk_free(&ss_i);
	chunk_free(&ss_r);
	initiator->destroy(initiator);
	responder->destroy(responder);
}
END_TEST

Suite *ml_kem_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("ml_kem");

	tc = tcase_create("encaps_decaps");
	tcase_add_loop_test(tc, test_encaps_decaps, 0, countof(ml_kem_tests));
	suite_add_tcase(s, tc);

	tc = tcase_create("invalid_public_key");
	tcase_add_loop_test(tc, test_invalid_public_key, 0, countof(ml_kem_tests));
	suite_add_tcase(s, tc);

	tc = tcase_create("invalid_ciphertext");
	tcase_add_loop_test(tc, test_invalid_ciphertext, 0, countof(ml_kem_tests));
	suite_add_tcase(s, tc);

	return s;
}
