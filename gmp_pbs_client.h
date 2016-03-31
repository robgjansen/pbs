/*
 * gmp_pbs_client.h
 *
 *  Created on: Mar 5, 2010
 *      Author: rob
 */

#ifndef GMP_PBS_CLIENT_H_
#define GMP_PBS_CLIENT_H_

#include "gmp_pbs_common.h"

typedef struct {
	mpz_t t1;
	mpz_t t2;
	mpz_t t3;
	mpz_t t4;
	mpz_t epsilon;
	mpz_t r;
	mpz_t c;
	mpz_t s;
	mpz_t d;
	mpz_t e;
	mpz_t a;
	mpz_t b;
	gmp_pbs_key pk;
	gmp_pbs_parameters parameters;
	gmp_pbs_signature signature;
	gmp_randstate_t random;
	gmp_pbs_workspace workspace;
} gmp_pbs_client_state;

void gmp_pbs_client_init(gmp_pbs_client_state *state);
void gmp_pbs_client_free(gmp_pbs_client_state *state);
void gmp_pbs_client_reset(gmp_pbs_client_state *state);

void gmp_pbs_client_sign_start(gmp_pbs_client_state *state, char *info, char *message);
int gmp_pbs_client_sign_finish(gmp_pbs_client_state *state);

void gmp_pbs_client_print(gmp_pbs_client_state *state, FILE *filep);

#endif /* GMP_PBS_CLIENT_H_ */
