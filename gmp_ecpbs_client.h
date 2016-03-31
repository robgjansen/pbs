/*
 * gmp_ecpbs_client.h
 *
 *  Created on: Mar 5, 2010
 *      Author: rob
 */

#ifndef GMP_ECPBS_CLIENT_H_
#define GMP_ECPBS_CLIENT_H_

#include "gmp_ecpbs_common.h"

typedef struct {
	big t1;
	big t2;
	big t3;
	big t4;
	big epsilon;
	big r;
	big c;
	big s;
	big d;
	big e;
	epoint *a;
	epoint *b;
	gmp_ecpbs_pk pk;
	gmp_ecpbs_parameters parameters;
	gmp_ecpbs_signature signature;
	gmp_ecpbs_workspace workspace;
} gmp_ecpbs_state;

void gmp_ecpbs_init(gmp_ecpbs_state *state);
void gmp_ecpbs_free(gmp_ecpbs_state *state);
void gmp_ecpbs_reset(gmp_ecpbs_state *state);
void gmp_ecpbs_print(gmp_ecpbs_state *state, FILE *filep);

void gmp_ecpbs_sign_start(gmp_ecpbs_state *state, char *info, char *message);
int gmp_ecpbs_sign_finish(gmp_ecpbs_state *state);

#endif /* GMP_ECPBS_CLIENT_H_ */
