/*
 * gmp_pbs_common.c
 *
 *  Created on: Mar 5, 2010
 *      Author: rob
 */

#include <openssl/sha.h>
#include "gmp_pbs_common.h"

// FIXME update these locations dynamically
char *pk_filename = "keys/schnor.public";
char *sk_filename = "keys/schnor.private";
char *param_filename = "keys/schnor.parameters";

int gmp_pbs_import_parameters(gmp_pbs_parameters *parameters, char *filename) {
	FILE *fp;

	/* get public curve parameters */
	fp = fopen(filename, "rt");
	if (fp == NULL) {
		printf("file %s does not exist\n", filename);
		return 0;
	}

	/* import parameters in base 16 (hex)  */
	mpz_inp_str(parameters->p, fp, 16);
	mpz_inp_str(parameters->q, fp, 16);
	mpz_inp_str(parameters->g, fp, 16);

	fclose(fp);
	return 1;
}

int gmp_pbs_import_key(gmp_pbs_key *key, char *filename) {
	FILE *fp;

	fp = fopen(filename, "rt");
	if (fp == NULL) {
		printf("file %s does not exist\n", filename);
		return 0;
	}

	/* import key in base 16 (hex) */
	mpz_inp_str(key->key, fp, 16);

	fclose(fp);
	return 1;
}

/* the F hash in Abe&Okamoto;  F: {0,1}* -> <g>
 * this function uses work1 and work2 from workspace */
void gmp_pbs_Fhash(mpz_t result, char *info, gmp_pbs_parameters *parameters,
		gmp_pbs_workspace *workspace) {
	gmp_pbs_Hhash(workspace->work2, info, parameters, workspace);
	mpz_powm(result, parameters->g, workspace->work2, parameters->p);
}

/* the H hash in Abe&Okamoto;  H: {0,1}* -> Z_q
 * this function uses work1 from workspace */
void gmp_pbs_Hhash(mpz_t result, char *info, gmp_pbs_parameters *parameters,
		gmp_pbs_workspace *workspace) {
	unsigned char *out;

	/* FIXME move this to workspace to avoid allocations during verify */
	/* temporary space to hold the binary result of the hash */
	out = calloc(20, sizeof(unsigned char));

	/* do the hash(info) operation */
	SHA1((unsigned char*) info, strlen(info), out);

	/* convert the hash */
	//	hash = BN_bin2bn(out, 20, NULL);
	mpz_import(workspace->work1, 20, 1, sizeof(out[0]), 0, 0, out);

	/* free the temporary space */
	free(out);

	/* do the mod q operation */
	mpz_mod(result, workspace->work1, parameters->q);
}

/* computes: epsilon = H(alpha|beta|z|message)
 * result will be taken mod q
 * this function uses work1 from workspace */
void gmp_pbs_hash_epsilon(mpz_t result, mpz_t alpha, mpz_t beta, mpz_t z,
		char *message, gmp_pbs_parameters *parameters, gmp_pbs_workspace *workspace) {
	int buffer_len, alpha_len, beta_len, z_len, msg_len;
	char *buffer, *pos;

	alpha_len = mpz_sizeinbase(alpha, 2);
	beta_len = mpz_sizeinbase(beta, 2);
	z_len = mpz_sizeinbase(z, 2);
	msg_len = strlen(message);

	/* need space for alpha,beta,z,message */
	buffer_len = alpha_len + beta_len + z_len + msg_len + 1;

	buffer = calloc(1, buffer_len);
	pos = buffer;
	mpz_export(pos, NULL, 1, alpha_len, 0, 0, alpha);
	pos += alpha_len;
	mpz_export(pos, NULL, 1, beta_len, 0, 0, beta);
	pos += beta_len;
	mpz_export(pos, NULL, 1, z_len, 0, 0, z);
	pos += z_len;
	memcpy(pos, message, strlen(message));
	gmp_pbs_Hhash(result, buffer, parameters, workspace);
	free(buffer);
}

int gmp_pbs_verify(gmp_pbs_signature *signature, char *info, char *message,
		gmp_pbs_parameters *parameters, gmp_pbs_key *pk,
		gmp_pbs_workspace *workspace) {

	/* compute z */
	gmp_pbs_Fhash(workspace->z, info, parameters, workspace);

	/* compute beta */
	mpz_powm(workspace->work1, workspace->z, signature->delta, parameters->p);
	mpz_powm(workspace->work2, parameters->g, signature->sigma, parameters->p);
	mpz_mul(workspace->work3, workspace->work1, workspace->work2);
	mpz_mod(workspace->beta, workspace->work3, parameters->p);

	/* compute alpha */
	mpz_powm(workspace->work1, pk->key, signature->omega, parameters->p);
	mpz_powm(workspace->work2, parameters->g, signature->rho, parameters->p);
	mpz_mul(workspace->work3, workspace->work1, workspace->work2);
	mpz_mod(workspace->alpha, workspace->work3, parameters->p);

	/* compute signature verification
	 * this is out of order because of the workspace usage*/
	mpz_add(workspace->work1, signature->omega, signature->delta);
	mpz_mod(workspace->work2, workspace->work1, parameters->q);

	/* hash values computed values */
	gmp_pbs_hash_epsilon(workspace->work3, workspace->alpha, workspace->beta,
			workspace->z, message, parameters, workspace);

	return mpz_cmp(workspace->work2, workspace->work3);
}

void gmp_pbs_print(FILE *fp, mpz_t num, char *msg) {
	fprintf(fp, "%s\t\t", msg);
	mpz_out_str(fp, 16, num);
	fprintf(fp, "\n");
}
