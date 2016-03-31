/*
 * mcl_ecpbs_bank.c
 *
 *  Created on: Feb 27, 2010
 *      Author: rob
 */

#include "mcl_ecpbs_common.h"
#include "mcl_ecpbs_bank.h"

void mcl_ecpbs_init_bank(mcl_ecpbs_bank_state *state) {
	epoint *test;
	mcl_ecpbs_import_parameters(&state->parameters);

	state->u = mirvar(0);
	state->r = mirvar(0);
	state->c = mirvar(0);
	state->s = mirvar(0);
	state->d = mirvar(0);
	state->e = mirvar(0);
	state->a = epoint_init();
	state->b = epoint_init();

	state->sk.key = mirvar(0);
	state->pk.key = epoint_init();

	mcl_ecpbs_import_pk(&state->pk);
	mcl_ecpbs_import_sk(&state->sk);

	/* sanity check, g^x =? y */
	test = epoint_init();
	ecurve_mult(state->sk.key, state->parameters.g, test);
	epoint_norm(test);
	if(!epoint_comp(test, state->pk.key)){
		printf("Failed sanity check during bank initialization: g^x != pk\n");
	}
	epoint_free(test);

	mcl_ecpbs_reset_bank(state);
}

void mcl_ecpbs_reset_bank(mcl_ecpbs_bank_state *state) {
	zero(state->u);
	zero(state->r);
	zero(state->c);
	zero(state->s);
	zero(state->d);
	zero(state->e);
	zero(state->a->X);
	zero(state->a->Y);
	zero(state->b->X);
	zero(state->b->Y);

	bigrand(state->parameters.q, state->u);
	bigrand(state->parameters.q, state->s);
	bigrand(state->parameters.q, state->d);
}

void mcl_ecpbs_free_bank(mcl_ecpbs_bank_state *state) {
	mirkill(state->u);
	mirkill(state->r);
	mirkill(state->c);
	mirkill(state->s);
	mirkill(state->d);
	mirkill(state->e);
	epoint_free(state->a);
	epoint_free(state->b);

	mirkill(state->sk.key);
	epoint_free(state->pk.key);

	mirkill(state->parameters.A);
	mirkill(state->parameters.B);
	mirkill(state->parameters.p);
	mirkill(state->parameters.q);
	epoint_free(state->parameters.g);
}

void mcl_ecpbs_print_bank(mcl_ecpbs_bank_state *state, FILE *filep){
	fprintf(filep, "==========PRINTING BANK STATE==========\n");

	mcl_ecpbs_printbig(state->u, "u");
	mcl_ecpbs_printbig(state->r, "r");
	mcl_ecpbs_printbig(state->c, "c");
	mcl_ecpbs_printbig(state->s, "s");
	mcl_ecpbs_printbig(state->d, "d");
	mcl_ecpbs_printbig(state->e, "e");

	mcl_ecpbs_printpoint(state->a, "a->x,y");
	mcl_ecpbs_printpoint(state->b, "b->x,y");

//	mcl_ecpbs_printbig(state->sk.key, "sk");
	mcl_ecpbs_printpoint(state->pk.key, "pk->x,y");

	mcl_ecpbs_printbig(state->parameters.A, "A");
	mcl_ecpbs_printbig(state->parameters.B, "B");
	mcl_ecpbs_printbig(state->parameters.p, "p");
	mcl_ecpbs_printbig(state->parameters.q, "q");
	mcl_ecpbs_printpoint(state->parameters.g, "g->x,y");

	fprintf(filep, "==========DONE==========\n\n");
}

void mcl_ecpbs_sign_start_bank(mcl_ecpbs_bank_state *state, char* info) {
	epoint *z = epoint_init();

	mcl_ecpbs_Fhash(z, info, &state->parameters);
	ecurve_mult(state->u, state->parameters.g, state->a);
	ecurve_mult2(state->s, state->parameters.g, state->d, z, state->b);

	epoint_free(z);
}

void mcl_ecpbs_sign_finish_bank(mcl_ecpbs_bank_state *state) {
	big temp = mirvar(0);

	subtract(state->e, state->d, state->c);
	mcl_ecpbs_mod(state->c, state->parameters.q);

	/* compute (c*x mod q), use "mad" to avoid buffer size problems of "multiply" */
	mad(state->c, state->sk.key, state->c, state->parameters.q, state->parameters.q, temp);
	subtract(state->u, temp, state->r);
	mcl_ecpbs_mod(state->r, state->parameters.q);

	mirkill(temp);
}
