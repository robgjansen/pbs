/*
 * gmp_pbs_bank.h
 *
 *  Created on: Mar 5, 2010
 *      Author: rob
 */

#ifndef GMP_PBS_BANK_H_
#define GMP_PBS_BANK_H_

#include "gmp_pbs_common.h"

typedef struct {
	mpz_t u;
	mpz_t r;
	mpz_t c;
	mpz_t s;
	mpz_t d;
	mpz_t e;
	mpz_t a;
	mpz_t b;
	gmp_pbs_key sk;
	gmp_pbs_key pk;
	gmp_pbs_parameters parameters;
	gmp_randstate_t random;
	gmp_pbs_workspace workspace;
} gmp_pbs_bank_state;

void gmp_pbs_bank_init(gmp_pbs_bank_state *state);
void gmp_pbs_bank_free(gmp_pbs_bank_state *state);
void gmp_pbs_bank_reset(gmp_pbs_bank_state *state);

void gmp_pbs_bank_sign_start(gmp_pbs_bank_state *state, char* info);
void gmp_pbs_bank_sign_finish(gmp_pbs_bank_state *state);

void gmp_pbs_bank_print(gmp_pbs_bank_state *state, FILE *filep);

#endif /* GMP_PBS_BANK_H_ */
