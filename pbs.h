/*
 * pbs.h
 *
 *  Created on: Feb 21, 2010
 *      Author: Rob Jansen
 */

#ifndef PBS_H_
#define PBS_H_

#include <openssl/bn.h>

typedef struct {
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *g;
} pbs_parameters;

typedef struct {
	BIGNUM *y;
} pbs_pk;

typedef struct {
	BIGNUM *x;

} pbs_sk;

typedef struct {
	BIGNUM *d;
	BIGNUM *u;
	BIGNUM *s;
} pbs_bank_state;

typedef struct {
	BIGNUM *t1;
	BIGNUM *t2;
	BIGNUM *t3;
	BIGNUM *t4;
	BIGNUM *epsilon;
} pbs_client_state;

typedef struct {
	BIGNUM *rho;
	BIGNUM *omega;
	BIGNUM *sigma;
	BIGNUM *delta;
} pbs_signature;

typedef struct {
	BIGNUM *left;
	BIGNUM *right;
	BIGNUM *temp1;
	BIGNUM *z;
	BN_CTX *ctx;
} pbs_workspace;

int load_parameters(pbs_parameters *pbs);

void free_parameters(pbs_parameters *pbs);

int gen_keys(pbs_parameters *pbs, pbs_sk *sk, pbs_pk *pk);

int load_keys(pbs_sk *sk, pbs_pk *pk);

void free_keys(pbs_sk *sk, pbs_pk *pk);

void free_client_state(pbs_client_state *state);

void free_bank_state(pbs_bank_state *state);

void free_signature(pbs_signature *signature);

void free_workspace(pbs_workspace *workspace);

int get_random_mod(BIGNUM *result, BIGNUM *mod);

int hash_group(BIGNUM *result, char *info, pbs_parameters *pbs);

int hash_mod(BIGNUM *result, char *info, BIGNUM *mod);

int bank_sign_init(BIGNUM *a, BIGNUM *b, pbs_bank_state *state, char *info,
		pbs_parameters *pbs);

int bank_sign_update(BIGNUM *r, BIGNUM *c, BIGNUM *s, BIGNUM *d,
		pbs_bank_state *state, pbs_parameters *pbs, pbs_sk *sk, BIGNUM *e);

int sign_init(pbs_client_state *state, pbs_signature *signature,
		pbs_workspace *workspace);

int sign_update(BIGNUM *e, pbs_client_state *state, pbs_parameters *pbs,
		pbs_pk *pk, char *message, char *info, BIGNUM *a, BIGNUM *b);

int sign_final(pbs_signature *signature, BIGNUM *r, BIGNUM *c, BIGNUM *s,
		BIGNUM *d, pbs_client_state *state, pbs_parameters *pbs);

int verify(pbs_signature *signature, pbs_pk *pk, pbs_parameters *pbs,
		char *info, char *message, pbs_workspace *workspace);

void printBN(BIGNUM *bn, char *msg);

#endif /* PBS_H_ */
