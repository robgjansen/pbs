/*
 * mcl_ecpbs_bank.h
 *
 *  Created on: Feb 27, 2010
 *      Author: rob
 */

#ifndef MCL_ECPBS_BANK_H_
#define MCL_ECPBS_BANK_H_

#include "mcl_ecpbs_common.h"

typedef struct {
	big u;
	big r;
	big c;
	big s;
	big d;
	big e;
	epoint *a;
	epoint *b;
	mcl_ecpbs_sk sk;
	mcl_ecpbs_pk pk;
	mcl_ecpbs_parameters parameters;
} mcl_ecpbs_bank_state;

void mcl_ecpbs_init_bank(mcl_ecpbs_bank_state *state);
void mcl_ecpbs_free_bank(mcl_ecpbs_bank_state *state);
void mcl_ecpbs_reset_bank(mcl_ecpbs_bank_state *state);
void mcl_ecpbs_print_bank(mcl_ecpbs_bank_state *state, FILE *filep);

void mcl_ecpbs_sign_start_bank(mcl_ecpbs_bank_state *state, char *info);
void mcl_ecpbs_sign_finish_bank(mcl_ecpbs_bank_state *state);

#endif /* MCL_ECPBS_BANK_H_ */
