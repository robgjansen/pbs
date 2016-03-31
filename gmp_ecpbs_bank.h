/*
 * gmp_ecpbs_bank.h
 *
 *  Created on: Mar 5, 2010
 *      Author: rob
 */

#ifndef GMP_ECPBS_BANK_H_
#define GMP_ECPBS_BANK_H_

#include "gmp_ecpbs_common.h"

typedef struct {
	big u;
	big r;
	big c;
	big s;
	big d;
	big e;
	epoint *a;
	epoint *b;
	gmp_ecpbs_sk sk;
	gmp_ecpbs_pk pk;
	gmp_ecpbs_parameters parameters;
} gmp_ecpbs_bank_state;

void gmp_ecpbs_init_bank(gmp_ecpbs_bank_state *state);
void gmp_ecpbs_free_bank(gmp_ecpbs_bank_state *state);
void gmp_ecpbs_reset_bank(gmp_ecpbs_bank_state *state);
void gmp_ecpbs_print_bank(gmp_ecpbs_bank_state *state, FILE *filep);

void gmp_ecpbs_sign_start_bank(gmp_ecpbs_bank_state *state, char *info);
void gmp_ecpbs_sign_finish_bank(gmp_ecpbs_bank_state *state);

#endif /* GMP_ECPBS_BANK_H_ */
