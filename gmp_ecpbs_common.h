/*
 * gmp_ecpbs_common.h
 *
 *  Created on: Mar 5, 2010
 *      Author: rob
 */

#ifndef GMP_ECPBS_COMMON_H_
#define GMP_ECPBS_COMMON_H_

#include <stdlib.h>
#include <gmp.h>
#include "miracl/miracl.h"

typedef struct {
	big p;
	big q;
	big A;
	big B;
	epoint *g;
} gmp_ecpbs_parameters;

typedef struct {
	big rho;
	big omega;
	big sigma;
	big delta;
} gmp_ecpbs_signature;

typedef struct {
	epoint *key;
} gmp_ecpbs_pk;

typedef struct {
	big key;
} gmp_ecpbs_sk;

typedef struct {
	big result;
	big check;
	epoint *alpha;
	epoint *beta;
	epoint *z;
} gmp_ecpbs_workspace;

void gmp_ecpbs_import_pk(gmp_ecpbs_pk *pk);
void gmp_ecpbs_import_sk(gmp_ecpbs_sk *sk);

/**
 * Imports the public curve parameters from file 'ec.parameters' in the
 * current directory. Each parameter in the file is on a separate line
 * in the following order: bits(p), p, a, b, q, x, y.
 *
 * The curve is y^2=x^3+Ax+b mod p.
 *
 * The domain information is {p,A,B,q,x,y}, where A and B are
 * curve parameters, (x,y) are a point of order q, p is the prime
 * modulus, and q is the order of the point (x,y).
 */
void gmp_ecpbs_import_parameters(gmp_ecpbs_parameters *parameters);

void gmp_ecpbs_mod(big x, big y);
void gmp_ecpbs_Fhash(epoint *result, char *info, gmp_ecpbs_parameters *pbs);
void gmp_ecpbs_Hhash(big result, char *info, big m);

void gmp_ecpbs_hash_epsilon(big result, epoint *alpha, epoint *beta, epoint *z,
		char *message, gmp_ecpbs_parameters *parameters);
int gmp_ecpbs_verify(gmp_ecpbs_signature *signature, char *info, char *message,
		gmp_ecpbs_parameters *parameters, gmp_ecpbs_pk *pk, gmp_ecpbs_workspace *workspace);

void gmp_ecpbs_printpoint(epoint *p, char *msg);
void gmp_ecpbs_printbig(big b, char *msg);

#endif /* GMP_ECPBS_COMMON_H_ */
