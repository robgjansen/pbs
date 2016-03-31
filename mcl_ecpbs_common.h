/*
 * mcl_ecpbs_common.h
 *
 *  Created on: Feb 27, 2010
 *      Author: rob
 */

#ifndef MCL_ECPBS_COMMON_H_
#define MCL_ECPBS_COMMON_H_

#include <stdlib.h>
#include "miracl/miracl.h"

typedef struct {
	big p;
	big q;
	big A;
	big B;
	epoint *g;
} mcl_ecpbs_parameters;

typedef struct {
	big rho;
	big omega;
	big sigma;
	big delta;
} mcl_ecpbs_signature;

typedef struct {
	epoint *key;
} mcl_ecpbs_pk;

typedef struct {
	big key;
} mcl_ecpbs_sk;

typedef struct {
	big result;
	big check;
	epoint *alpha;
	epoint *beta;
	epoint *z;
} mcl_ecpbs_workspace;

void mcl_ecpbs_import_pk(mcl_ecpbs_pk *pk);
void mcl_ecpbs_import_sk(mcl_ecpbs_sk *sk);

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
void mcl_ecpbs_import_parameters(mcl_ecpbs_parameters *parameters);

void mcl_ecpbs_mod(big x, big y);
void mcl_ecpbs_Fhash(epoint *result, char *info, mcl_ecpbs_parameters *pbs);
void mcl_ecpbs_Hhash(big result, char *info, big m);

void mcl_ecpbs_hash_epsilon(big result, epoint *alpha, epoint *beta, epoint *z,
		char *message, mcl_ecpbs_parameters *parameters);
int mcl_ecpbs_verify(mcl_ecpbs_signature *signature, char *info, char *message,
		mcl_ecpbs_parameters *parameters, mcl_ecpbs_pk *pk, mcl_ecpbs_workspace *workspace);

void mcl_ecpbs_printpoint(epoint *p, char *msg);
void mcl_ecpbs_printbig(big b, char *msg);

#endif /* MCL_ECPBS_COMMON_H_ */
