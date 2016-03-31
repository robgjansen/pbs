/*
 * gmp_pbs_client.c
 *
 *  Created on: Mar 5, 2010
 *      Author: rob
 */
/* FIXME many of initializations and frees are shared between client and bank and should be extracted to gmp_pbs_common */

#include "gmp_pbs_common.h"
#include "gmp_pbs_client.h"

void gmp_pbs_client_init(gmp_pbs_client_state *state) {
	/* initiate the state for a signature */
	mpz_init(state->r);
	mpz_init(state->c);
	mpz_init(state->s);
	mpz_init(state->d);
	mpz_init(state->e);
	mpz_init(state->a);
	mpz_init(state->b);

	mpz_init(state->t1);
	mpz_init(state->t2);
	mpz_init(state->t3);
	mpz_init(state->t4);
	mpz_init(state->epsilon);

	mpz_init(state->signature.delta);
	mpz_init(state->signature.rho);
	mpz_init(state->signature.sigma);
	mpz_init(state->signature.omega);

	/* workspace used by the client */
	mpz_init(state->workspace.alpha);
	mpz_init(state->workspace.beta);
	mpz_init(state->workspace.z);
	mpz_init(state->workspace.work1);
	mpz_init(state->workspace.work2);
	mpz_init(state->workspace.work3);

	/* parameters and keys */
	mpz_init(state->parameters.p);
	mpz_init(state->parameters.q);
	mpz_init(state->parameters.g);
	mpz_init(state->pk.key);

	/* import our parameters and keys from file */
	gmp_pbs_import_parameters(&state->parameters, param_filename);
	gmp_pbs_import_key(&state->pk, pk_filename);

	/* our random generator, mersenne twister */
	gmp_randinit_mt(state->random);
	/* FIXME get random seed from true random source */
	gmp_randseed_ui(state->random, 987654321);

	gmp_pbs_client_reset(state);
}

void gmp_pbs_client_reset(gmp_pbs_client_state *state) {
	mpz_urandomm(state->t1, state->random, state->parameters.q);
	mpz_urandomm(state->t2, state->random, state->parameters.q);
	mpz_urandomm(state->t3, state->random, state->parameters.q);
	mpz_urandomm(state->t4, state->random, state->parameters.q);
}

void gmp_pbs_client_free(gmp_pbs_client_state *state) {
	/* free state */
	mpz_clear(state->r);
	mpz_clear(state->c);
	mpz_clear(state->s);
	mpz_clear(state->d);
	mpz_clear(state->e);
	mpz_clear(state->a);
	mpz_clear(state->b);

	mpz_clear(state->t1);
	mpz_clear(state->t2);
	mpz_clear(state->t3);
	mpz_clear(state->t4);
	mpz_clear(state->epsilon);

	/* clear signature */
	mpz_clear(state->signature.delta);
	mpz_clear(state->signature.rho);
	mpz_clear(state->signature.sigma);
	mpz_clear(state->signature.omega);

	/* workspace used by the bank */
	mpz_clear(state->workspace.alpha);
	mpz_clear(state->workspace.beta);
	mpz_clear(state->workspace.z);
	mpz_clear(state->workspace.work1);
	mpz_clear(state->workspace.work2);
	mpz_clear(state->workspace.work3);

	/* free parameters and keys */
	mpz_clear(state->parameters.p);
	mpz_clear(state->parameters.q);
	mpz_clear(state->parameters.g);
	mpz_clear(state->pk.key);
}

void gmp_pbs_client_sign_start(gmp_pbs_client_state *state, char *info,
		char *message) {
	/* compute z */
	gmp_pbs_Fhash(state->workspace.z, info, &state->parameters, &state->workspace);

	/* compute alpha */
	mpz_powm(state->workspace.work1, state->parameters.g, state->t1, state->parameters.p);
	mpz_mul(state->workspace.work2, state->workspace.work1, state->a);
	mpz_mod(state->workspace.work1, state->workspace.work2, state->parameters.p);

	mpz_powm(state->workspace.work2, state->pk.key, state->t2, state->parameters.p);
	mpz_mul(state->workspace.work3, state->workspace.work1, state->workspace.work2);
	mpz_mod(state->workspace.alpha, state->workspace.work3, state->parameters.p);

	/* compute beta */
	mpz_powm(state->workspace.work1, state->parameters.g, state->t3, state->parameters.p);
	mpz_mul(state->workspace.work2, state->workspace.work1, state->b);
	mpz_mod(state->workspace.work1, state->workspace.work2, state->parameters.p);

	mpz_powm(state->workspace.work2, state->workspace.z, state->t4, state->parameters.p);
	mpz_mul(state->workspace.work3, state->workspace.work1, state->workspace.work2);
	mpz_mod(state->workspace.beta, state->workspace.work3, state->parameters.p);

	/* compute epsilon */
	gmp_pbs_hash_epsilon(state->epsilon, state->workspace.alpha, state->workspace.beta, state->workspace.z, message,
			&state->parameters, &state->workspace);

	/* compute e */
	mpz_sub(state->workspace.work1, state->epsilon, state->t2);
	mpz_mod(state->workspace.work2, state->workspace.work1, state->parameters.q);
	mpz_sub(state->workspace.work1, state->workspace.work2, state->t4);
	mpz_mod(state->e, state->workspace.work1, state->parameters.q);
}

int gmp_pbs_client_sign_finish(gmp_pbs_client_state *state) {
	/* compute rho */
	mpz_add(state->workspace.work1, state->r, state->t1);
	mpz_mod(state->signature.rho, state->workspace.work1, state->parameters.q);

	/* compute omega */
	mpz_add(state->workspace.work1, state->c, state->t2);
	mpz_mod(state->signature.omega, state->workspace.work1, state->parameters.q);

	/* compute sigma */
	mpz_add(state->workspace.work1, state->s, state->t3);
	mpz_mod(state->signature.sigma, state->workspace.work1, state->parameters.q);

	/* compute delta */
	mpz_add(state->workspace.work1, state->d, state->t4);
	mpz_mod(state->signature.delta, state->workspace.work1, state->parameters.q);

	/* consistency check for signature */
	mpz_add(state->workspace.work1, state->signature.omega, state->signature.delta);
	mpz_mod(state->workspace.work2, state->workspace.work1, state->parameters.q);

	return mpz_cmp(state->workspace.work2, state->epsilon);
}

void gmp_pbs_client_print(gmp_pbs_client_state *state, FILE *filep) {
	fprintf(filep, "==========PRINTING CLIENT STATE==========\n");

	gmp_pbs_print(filep, state->t1, "t1");
	gmp_pbs_print(filep, state->t2, "t2");
	gmp_pbs_print(filep, state->t3, "t3");
	gmp_pbs_print(filep, state->t4, "t4");

	gmp_pbs_print(filep, state->epsilon, "epsilon");
	gmp_pbs_print(filep, state->r, "r");
	gmp_pbs_print(filep, state->c, "c");
	gmp_pbs_print(filep, state->s, "s");
	gmp_pbs_print(filep, state->d, "d");
	gmp_pbs_print(filep, state->e, "e");

	gmp_pbs_print(filep, state->a, "a");
	gmp_pbs_print(filep, state->b, "b");

	gmp_pbs_print(filep, state->workspace.alpha, "workspace alpha");
	gmp_pbs_print(filep, state->workspace.beta, "workspace beta");
	gmp_pbs_print(filep, state->workspace.z, "workspace z");
	gmp_pbs_print(filep, state->workspace.work1, "workspace work1");
	gmp_pbs_print(filep, state->workspace.work2, "workspace work2");
	gmp_pbs_print(filep, state->workspace.work3, "workspace work3");

	gmp_pbs_print(filep, state->signature.rho, "rho");
	gmp_pbs_print(filep, state->signature.omega, "delta");
	gmp_pbs_print(filep, state->signature.sigma, "sigma");
	gmp_pbs_print(filep, state->signature.delta, "delta");

	gmp_pbs_print(filep, state->pk.key, "pk");

	gmp_pbs_print(filep, state->parameters.p, "p");
	gmp_pbs_print(filep, state->parameters.q, "q");
	gmp_pbs_print(filep, state->parameters.g, "g");

	fprintf(filep, "==========DONE==========\n\n");
}
