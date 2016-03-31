/*
 * gmp_ecpbs_client.c
 *
 *  Created on: Mar 5, 2010
 *      Author: rob
 */

#include "gmp_ecpbs_common.h"
#include "gmp_ecpbs_client.h"

void gmp_ecpbs_init(gmp_ecpbs_state *state) {
	gmp_ecpbs_import_parameters(&state->parameters);

	state->t1 = mirvar(0);
	state->t2 = mirvar(0);
	state->t3 = mirvar(0);
	state->t4 = mirvar(0);
	state->epsilon = mirvar(0);
	state->r = mirvar(0);
	state->c = mirvar(0);
	state->s = mirvar(0);
	state->d = mirvar(0);
	state->e = mirvar(0);
	state->a = epoint_init();
	state->b = epoint_init();

	state->signature.delta = mirvar(0);
	state->signature.rho = mirvar(0);
	state->signature.sigma = mirvar(0);
	state->signature.omega = mirvar(0);

	state->workspace.alpha = epoint_init();
	state->workspace.beta = epoint_init();
	state->workspace.z = epoint_init();
	state->workspace.check = mirvar(0);
	state->workspace.result = mirvar(0);

	state->pk.key = epoint_init();

	gmp_ecpbs_import_pk(&state->pk);

	gmp_ecpbs_reset(state);
}

void gmp_ecpbs_reset(gmp_ecpbs_state *state) {
	zero(state->t1);
	zero(state->t2);
	zero(state->t3);
	zero(state->t4);
	zero(state->epsilon);
	zero(state->r);
	zero(state->c);
	zero(state->s);
	zero(state->d);
	zero(state->e);
	zero(state->a->X);
	zero(state->a->Y);
	zero(state->b->X);
	zero(state->b->Y);

	zero(state->signature.delta);
	zero(state->signature.rho);
	zero(state->signature.sigma);
	zero(state->signature.omega);

	zero(state->workspace.check);
	zero(state->workspace.result);
	zero(state->workspace.alpha->X);
	zero(state->workspace.alpha->Y);
	zero(state->workspace.beta->X);
	zero(state->workspace.beta->Y);
	zero(state->workspace.z->X);
	zero(state->workspace.z->Y);

	bigrand(state->parameters.q, state->t1);
	bigrand(state->parameters.q, state->t2);
	bigrand(state->parameters.q, state->t3);
	bigrand(state->parameters.q, state->t4);
}

void gmp_ecpbs_free(gmp_ecpbs_state *state) {
	mirkill(state->t1);
	mirkill(state->t2);
	mirkill(state->t3);
	mirkill(state->t4);
	mirkill(state->epsilon);
	mirkill(state->r);
	mirkill(state->c);
	mirkill(state->s);
	mirkill(state->d);
	mirkill(state->e);
	epoint_free(state->a);
	epoint_free(state->b);

	mirkill(state->signature.delta);
	mirkill(state->signature.rho);
	mirkill(state->signature.sigma);
	mirkill(state->signature.omega);

	mirkill(state->workspace.check);
	mirkill(state->workspace.result);
	epoint_free(state->workspace.alpha);
	epoint_free(state->workspace.beta);
	epoint_free(state->workspace.z);

	epoint_free(state->pk.key);

	mirkill(state->parameters.A);
	mirkill(state->parameters.B);
	mirkill(state->parameters.p);
	mirkill(state->parameters.q);
	epoint_free(state->parameters.g);
}

void gmp_ecpbs_print(gmp_ecpbs_state *state, FILE *filep) {
	fprintf(filep, "==========PRINTING STATE==========\n");

	gmp_ecpbs_printbig(state->t1, "t1");
	gmp_ecpbs_printbig(state->t2, "t2");
	gmp_ecpbs_printbig(state->t3, "t3");
	gmp_ecpbs_printbig(state->t4, "t4");

	gmp_ecpbs_printbig(state->epsilon, "epsilon");
	gmp_ecpbs_printbig(state->r, "r");
	gmp_ecpbs_printbig(state->c, "c");
	gmp_ecpbs_printbig(state->s, "s");
	gmp_ecpbs_printbig(state->d, "d");
	gmp_ecpbs_printbig(state->e, "e");

	gmp_ecpbs_printpoint(state->a, "a->x,y");
	gmp_ecpbs_printpoint(state->b, "b->x,y");

	gmp_ecpbs_printbig(state->signature.rho, "rho");
	gmp_ecpbs_printbig(state->signature.omega, "delta");
	gmp_ecpbs_printbig(state->signature.sigma, "sigma");
	gmp_ecpbs_printbig(state->signature.delta, "delta");

	gmp_ecpbs_printpoint(state->pk.key, "pk->x,y");

	gmp_ecpbs_printbig(state->parameters.A, "A");
	gmp_ecpbs_printbig(state->parameters.B, "B");
	gmp_ecpbs_printbig(state->parameters.p, "p");
	gmp_ecpbs_printbig(state->parameters.q, "q");

	gmp_ecpbs_printpoint(state->parameters.g, "g->x,y");

	fprintf(filep, "==========DONE==========\n\n");
}

void gmp_ecpbs_sign_start(gmp_ecpbs_state *state, char *info, char *message) {
	epoint *alpha, *beta, *z;

	z = epoint_init();
	alpha = epoint_init();
	beta = epoint_init();

	gmp_ecpbs_Fhash(z, info, &state->parameters);
	ecurve_mult2(state->t1, state->parameters.g, state->t2, state->pk.key,
			alpha);
	ecurve_add(state->a, alpha);
	ecurve_mult2(state->t3, state->parameters.g, state->t4, z, beta);
	ecurve_add(state->b, beta);

	gmp_ecpbs_hash_epsilon(state->epsilon, alpha, beta, z, message,
			&state->parameters);

	subtract(state->epsilon, state->t2, state->e);
	subtract(state->e, state->t4, state->e);
	gmp_ecpbs_mod(state->e, state->parameters.q);

	epoint_free(z);
	epoint_free(alpha);
	epoint_free(beta);
}

int gmp_ecpbs_sign_finish(gmp_ecpbs_state *state) {
	int success;
	big final = mirvar(0);

	add(state->r, state->t1, state->signature.rho);
	gmp_ecpbs_mod(state->signature.rho, state->parameters.q);

	add(state->c, state->t2, state->signature.omega);
	gmp_ecpbs_mod(state->signature.omega, state->parameters.q);

	add(state->s, state->t3, state->signature.sigma);
	gmp_ecpbs_mod(state->signature.sigma, state->parameters.q);

	add(state->d, state->t4, state->signature.delta);
	gmp_ecpbs_mod(state->signature.delta, state->parameters.q);

	/* consistency check for signature */
	add(state->signature.omega, state->signature.delta, final);
	gmp_ecpbs_mod(final, state->parameters.q);
	success = mr_compare(state->epsilon, final) == 0;

	mirkill(final);
	return success;
}
