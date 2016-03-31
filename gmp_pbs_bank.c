/*
 * gmp_pbs_bank.c
 *
 *  Created on: Mar 5, 2010
 *      Author: rob
 */
/* FIXME many of initializations and frees are shared between client and bank and should be extracted to gmp_pbs_common */

#include "gmp_pbs_common.h"
#include "gmp_pbs_bank.h"

void gmp_pbs_bank_init(gmp_pbs_bank_state *state) {
	/* initiate the state for a signature */
	mpz_init(state->u);
	mpz_init(state->r);
	mpz_init(state->c);
	mpz_init(state->s);
	mpz_init(state->d);
	mpz_init(state->e);
	mpz_init(state->a);
	mpz_init(state->b);

	/* workspace used by the bank */
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
	mpz_init(state->sk.key);
	mpz_init(state->pk.key);

	/* import our parameters and keys from file */
	gmp_pbs_import_parameters(&state->parameters, param_filename);
	gmp_pbs_import_key(&state->sk, sk_filename);
	gmp_pbs_import_key(&state->pk, pk_filename);

	/* our random generator, mersenne twister */
	gmp_randinit_mt(state->random);
	/* FIXME get random seed from true random source */
	gmp_randseed_ui(state->random, 123456789);

	/* sanity check, g^x =? y */
	mpz_powm(state->workspace.work1, state->parameters.g, state->sk.key, state->parameters.p);
	if (mpz_cmp(state->workspace.work1, state->pk.key) != 0) {
		printf("Failed sanity check during bank initialization: g^x != pk\n");
	}

	/* get our required random state values */
	gmp_pbs_bank_reset(state);
}

void gmp_pbs_bank_reset(gmp_pbs_bank_state *state) {
	mpz_urandomm(state->u, state->random, state->parameters.q);
	mpz_urandomm(state->s, state->random, state->parameters.q);
	mpz_urandomm(state->d, state->random, state->parameters.q);
}

void gmp_pbs_bank_free(gmp_pbs_bank_state *state) {
	/* free state */
	mpz_clear(state->u);
	mpz_clear(state->r);
	mpz_clear(state->c);
	mpz_clear(state->s);
	mpz_clear(state->d);
	mpz_clear(state->e);
	mpz_clear(state->a);
	mpz_clear(state->b);

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
	mpz_clear(state->sk.key);
	mpz_clear(state->pk.key);
}

void gmp_pbs_bank_sign_start(gmp_pbs_bank_state *state, char* info) {
	/* compute z, place in work3 */
	gmp_pbs_Fhash(state->workspace.work3, info, &state->parameters,
			&state->workspace);

	/* compute b */
	mpz_powm(state->workspace.work1, state->workspace.work3, state->d, state->parameters.p);
	mpz_powm(state->workspace.work2, state->parameters.g, state->s, state->parameters.p);
	mpz_mul(state->workspace.work3, state->workspace.work1, state->workspace.work2);
	mpz_mod(state->b, state->workspace.work3, state->parameters.p);

	/* compute a */
	mpz_powm(state->a, state->parameters.g, state->u, state->parameters.p);
}

void gmp_pbs_bank_sign_finish(gmp_pbs_bank_state *state) {
	/* compute c */
	mpz_sub(state->workspace.work1, state->e, state->d);
	mpz_mod(state->c, state->workspace.work1, state->parameters.q);

	/* compute r */
	mpz_mul(state->workspace.work1, state->c, state->sk.key);
	mpz_mod(state->workspace.work2, state->workspace.work1, state->parameters.q);
	mpz_sub(state->workspace.work3, state->u, state->workspace.work2);
	mpz_mod(state->r, state->workspace.work3, state->parameters.q);
}

void gmp_pbs_bank_print(gmp_pbs_bank_state *state, FILE *filep){
	fprintf(filep, "==========PRINTING BANK STATE==========\n");

	gmp_pbs_print(filep, state->u, "u");
	gmp_pbs_print(filep, state->r, "r");
	gmp_pbs_print(filep, state->c, "c");
	gmp_pbs_print(filep, state->s, "s");
	gmp_pbs_print(filep, state->d, "d");
	gmp_pbs_print(filep, state->e, "e");

	gmp_pbs_print(filep, state->a, "a");
	gmp_pbs_print(filep, state->b, "b");
	gmp_pbs_print(filep, state->sk.key, "sk");
	gmp_pbs_print(filep, state->pk.key, "pk");

	gmp_pbs_print(filep, state->parameters.p, "p");
	gmp_pbs_print(filep, state->parameters.q, "q");
	gmp_pbs_print(filep, state->parameters.g, "g");

	fprintf(filep, "==========DONE==========\n\n");
}
