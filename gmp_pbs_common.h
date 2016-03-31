/*
 * gmp_pbs_common.h
 *
 *  Created on: Mar 5, 2010
 *      Author: rob
 */

#ifndef GMP_PBS_COMMON_H_
#define GMP_PBS_COMMON_H_

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <gmp.h>

extern char *pk_filename;
extern char *sk_filename;
extern char *param_filename;

typedef struct {
	mpz_t p;
	mpz_t q;
	mpz_t g;
} gmp_pbs_parameters;

typedef struct {
	mpz_t rho;
	mpz_t omega;
	mpz_t sigma;
	mpz_t delta;
} gmp_pbs_signature;

typedef struct {
	mpz_t key;
} gmp_pbs_key;

typedef struct {
	mpz_t alpha;
	mpz_t beta;
	mpz_t z;
	mpz_t work1;
	mpz_t work2;
	mpz_t work3;
} gmp_pbs_workspace;

int gmp_pbs_import_key(gmp_pbs_key *key, char *filename);
int gmp_pbs_import_parameters(gmp_pbs_parameters *parameters, char *filename);

void gmp_pbs_Fhash(mpz_t result, char *info, gmp_pbs_parameters *parameters,
		gmp_pbs_workspace *workspace);
void gmp_pbs_Hhash(mpz_t result, char *info, gmp_pbs_parameters *parameters,
		gmp_pbs_workspace *workspace);

void gmp_pbs_hash_epsilon(mpz_t result, mpz_t alpha, mpz_t beta, mpz_t z,
		char *message, gmp_pbs_parameters *parameters, gmp_pbs_workspace *workspace);

int gmp_pbs_verify(gmp_pbs_signature *signature, char *info, char *message,
		gmp_pbs_parameters *parameters, gmp_pbs_key *pk,
		gmp_pbs_workspace *workspace);

void gmp_pbs_print(FILE *fp, mpz_t num, char *msg);

#endif /* GMP_PBS_COMMON_H_ */
