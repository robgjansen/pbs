/*
 * mcl_ecpbs_client.h
 *
 *  Created on: Feb 27, 2010
 *      Author: rob
 */

#ifndef MCL_ECPBS_CLIENT_H_
#define MCL_ECPBS_CLIENT_H_

#include "mcl_ecpbs_common.h"

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
	mcl_ecpbs_pk pk;
	mcl_ecpbs_parameters parameters;
	mcl_ecpbs_signature signature;
	mcl_ecpbs_workspace workspace;
} mcl_ecpbs_state;

void mcl_ecpbs_init(mcl_ecpbs_state *state);
void mcl_ecpbs_free(mcl_ecpbs_state *state);
void mcl_ecpbs_reset(mcl_ecpbs_state *state);
void mcl_ecpbs_print(mcl_ecpbs_state *state, FILE *filep);

void mcl_ecpbs_sign_start(mcl_ecpbs_state *state, char *info, char *message);
int mcl_ecpbs_sign_finish(mcl_ecpbs_state *state);

#endif /* MCL_ECPBS_CLIENT_H_ */
