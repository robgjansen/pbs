/*
 * mcl_ecpbs_common.c
 *
 *  Created on: Feb 27, 2010
 *      Author: rob
 */

#include <string.h>
#include "mcl_ecpbs_common.h"

void mcl_ecpbs_import_parameters(mcl_ecpbs_parameters *parameters) {
	FILE *fp;
	int bits;
	big x, y;
	miracl *mip;

	/* get public curve parameters */
	fp = fopen("keys/ec160.parameters", "rt");
	if (fp == NULL) {
		printf("file ec.parameters does not exist\n");
		exit(0);
	}

	/* read in big number bitlength */
	fscanf(fp, "%d\n", &bits);

	/*
	 * Initialize the system, using HEX (base16) internally.
	 * The internal storage for each big number uses bits/4.
	 */
	mip = mirsys(bits / 4, 16);

	/* initialize memory for parameters */
	parameters->p = mirvar(0);
	parameters->A = mirvar(0);
	parameters->B = mirvar(0);
	parameters->q = mirvar(0);
	x = mirvar(0);
	y = mirvar(0);
	parameters->g = epoint_init();

	/* import parameters */
	/* p is the modulus */
	innum(parameters->p, fp);
	/* A and B are curve parameters */
	innum(parameters->A, fp);
	innum(parameters->B, fp);
	/* q is the order of (x,y) */
	innum(parameters->q, fp);
	/* (x,y) point on curve of order q */
	innum(x, fp);
	innum(y, fp);
	fclose(fp);

	/* FIXME randomize */
	irand(675822498);

	/* initialize curve - can use MR_PROJECTIVE, or MR_AFFINE */
	ecurve_init(parameters->A, parameters->B, parameters->p, MR_PROJECTIVE);

	/* check if x is valid on the curve */
	if (!epoint_x(x)) {
		printf(
				"Problem - imported x value of the generator is not on the active curve\n");
		exit(0);
	}

	/* initialize generator to the point of order q */
	if (!epoint_set(x, y, 0, parameters->g)) {
		printf("Problem - generator point (x,y) is not on the curve\n");
		exit(0);
	}

	mirkill(x);
	mirkill(y);
}

void mcl_ecpbs_import_pk(mcl_ecpbs_pk *pk) {
	FILE *fp;
	int compressed_y;
	big x;

	fp = fopen("keys/ec160.public", "rt");
	if (fp == NULL) {
		printf("file ec.public does not exist\n");
		exit(0);
	}

	x = mirvar(0);

	/* import the compressed y value */
	fscanf(fp, "%d", &compressed_y);
	/* import the x coordinate on the curve */
	innum(x, fp);
	fclose(fp);

	/* check if x is valid on the curve */
	if (!epoint_x(x)) {
		printf(
				"Problem - imported x value of the public key is not on the active curve\n");
		exit(0);
	}

	/* decompress point */
	if (!epoint_set(x, x, compressed_y, pk->key)) {
		printf("Problem - public key point (x,y) is not on the curve\n");
		exit(0);
	}

	mirkill(x);
}

void mcl_ecpbs_import_sk(mcl_ecpbs_sk *sk) {
	FILE *fp;
	fp = fopen("keys/ec160.private", "rt");
	if (fp == NULL) {
		printf("file ec.private does not exist\n");
		exit(0);
	}
	innum(sk->key, fp);
	fclose(fp);
}

/* computes x = x mod y and adjust so its always positive */
void mcl_ecpbs_mod(big x, big y) {
	divide(x, y, y);
	/* if negative, add back the modulus */
	while (size(x) < 0) {
		add(x, y, x);
	}
}

void mcl_ecpbs_Fhash(epoint *result, char *info, mcl_ecpbs_parameters *pbs) {
	big hash = mirvar(0);
	mcl_ecpbs_Hhash(hash, info, pbs->q);
	ecurve_mult(hash, pbs->g, result);
	mirkill(hash);
}

void mcl_ecpbs_Hhash(big result, char *info, big m) {
	char hash[20];
	int i;
	sha sh;
	shs_init(&sh);
	for (i = 0; info[i] != 0; i++) {
		shs_process(&sh, info[i]);
	}
	shs_hash(&sh, hash);
	bytes_to_big(20, hash, result);
	mcl_ecpbs_mod(result, m);
}

void mcl_ecpbs_hash_epsilon(big result, epoint *alpha, epoint *beta, epoint *z,
		char *message, mcl_ecpbs_parameters *parameters) {
	int buffer_len, num_bytes = 0;
	int big_size;
	char *buffer, *pos;

	/* miracl *mip = get_mip(); */
	/* FIXME do this dynamically: big_size_bits = mip->nib * 8; */
	big_size = 20;

	/* 6 bigs for X and Y of alpha,beta,and z */
	buffer_len = (6 * big_size) + strlen(message) + 1;

	epoint_norm(alpha);
	epoint_norm(beta);
	epoint_norm(z);

	/* compute: H(alpha->X|alpha->Y|beta->X|beta->Y|z->X|z->Y|msg) */
	buffer = calloc(1, buffer_len);
	pos = buffer;
	num_bytes = big_to_bytes(big_size, alpha->X, pos, FALSE);
	pos = pos + num_bytes;
	num_bytes = big_to_bytes(big_size, alpha->Y, pos, FALSE);
	pos = pos + num_bytes;
	num_bytes = big_to_bytes(big_size, beta->X, pos, FALSE);
	pos = pos + num_bytes;
	num_bytes = big_to_bytes(big_size, beta->Y, pos, FALSE);
	pos = pos + num_bytes;
	num_bytes = big_to_bytes(big_size, z->X, pos, FALSE);
	pos = pos + num_bytes;
	num_bytes = big_to_bytes(big_size, z->Y, pos, FALSE);
	pos = pos + num_bytes;
	memcpy(pos, message, strlen(message));

	mcl_ecpbs_Hhash(result, buffer, parameters->q);
	free(buffer);
}

int mcl_ecpbs_verify(mcl_ecpbs_signature *signature, char *info, char *message,
		mcl_ecpbs_parameters *parameters, mcl_ecpbs_pk *pk, mcl_ecpbs_workspace *workspace) {
	add(signature->omega, signature->delta, workspace->result);
	mcl_ecpbs_mod(workspace->result, parameters->q);

	mcl_ecpbs_Fhash(workspace->z, info, parameters);

	ecurve_mult2(signature->rho, parameters->g, signature->omega, pk->key,
			workspace->alpha);
	ecurve_mult2(signature->sigma, parameters->g, signature->delta,
			workspace->z, workspace->beta);

	mcl_ecpbs_hash_epsilon(workspace->check, workspace->alpha, workspace->beta,
			workspace->z, message, parameters);

	return mr_compare(workspace->result, workspace->check);
}

void mcl_ecpbs_printpoint(epoint *p, char *msg) {
	epoint_norm(p);
	fprintf(stdout, "%s\t\t", msg);
	otnum(p->X, stdout);
	fprintf(stdout, "\t\t");
	otnum(p->Y, stdout);
}

void mcl_ecpbs_printbig(big b, char *msg) {
	fprintf(stdout, "%s\t\t", msg);
	otnum(b, stdout);
}
