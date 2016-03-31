/*
 * pbs.c
 *
 *  Created on: Feb 21, 2010
 *      Author: Rob Jansen
 */

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/engine.h>
#include <string.h>

#include "pbs.h"

#define ERR 0
#define SCS 1

#undef DEBUG /* do we want debugging? */

#ifdef DEBUG

#define ERROR(ARGS) do { \
        fprintf(stderr, "ERROR at %s line %d: ", __FILE__, __LINE__); \
        fprintf(stderr, ARGS "\n"); \
        perror("errno shows"); \
        abort(); } while (0)

#define WARNING(ARGS) do { \
        fprintf(stderr, "WARNING at %s line %d: ", __FILE__, __LINE__); \
        fprintf(stderr, ARGS "\n"); \
        perror("errno shows"); } while (0)

#define VWARNING(FORMAT, ARGS...) do { \
        fprintf(stderr, "WARNING at %s line %d: ", __FILE__, __LINE__); \
        fprintf(stderr, FORMAT, ## ARGS); } while (0)

#define INFO(ARGS) do { \
        fprintf(stderr, "INFO at %s line %d: ", __FILE__, __LINE__); \
        fprintf(stderr, ARGS "\n"); } while (0)

#define VINFO(FORMAT, ARGS...) do { \
        fprintf(stderr, "INFO at %s line %d: ", __FILE__, __LINE__); \
        fprintf(stderr, FORMAT, ## ARGS); } while (0)

#else

#define ERROR(ARGS) do {abort();} while (0)
#define WARNING(ARGS) do {} while (0)
#define VWARNING(FORMAT, ARGS...) do {} while (0)
#define INFO(ARGS) do {} while (0)
#define VINFO(FORMAT, ARGS...) do {} while (0)

#endif

/* Schnorr-style parameters we will use for signature */
static char
		* hexp =
				"98E462268DA976E92AFDF5987BC071CA6AD039663338F368673808EFBA7F1EEBE03870E773F028C17CD08BAF6F5F4875A3BCE63206A6C995149E8700F2731767DB04C0BEFFA0D929962298E959E13E5495699B1ADD7117CE859D108B7CC758264C3A47FAE858AC6341E98E3ECD109A525F6892B3A5592E868832D5E5621A2955";
static char* hexq = "9B9BA5FF1975869AA2FC2724B20C657872EED7ED";
static char
		* hexg =
				"068239A1D2C22C7D86D5CD0DAE791CB1FA0E022AF5F9DF5F72280C2BCD0E94D61E5ACD13ECB5E56D319D65537CAE4AD525EACB8128F4922301F9F927D4B3424F820ECE82CA0A813ED3E81352A00B3A9D390ACE90BCCB8FC979AB9AB95BF6E1541E28A2614F5F1DAF456D5AB1A11275616874BE3D0269EFBF714EABC5D6CDBBF2";
/* public key y */
static char
		* hexy =
				"0B8E6BD6F233424D129334D6ED2B55C7F8D0FD346D9770518AD6903D6D2E1221195505A8D547F6AE4DE4B0BC767160023E5C9789B22AEDA9AD0B405C61F118B40A001A72C86FF93D22649907085B03E9DBFB75E823F458327341F6C4AC04EADC83E2EBF37356F4655F97C38676BA0247F9DE45CD934ABBD2D1C3EB8908B254F7";
/* private key x */
static char* hexx = "7E7A7FB03E642BDA4EBE7E9EF08A0B29A4097357";

int load_parameters(pbs_parameters *pbs) {
	pbs->p = BN_new();
	pbs->q = BN_new();
	pbs->g = BN_new();

	BN_hex2bn(&pbs->p, hexp);
	BN_hex2bn(&pbs->q, hexq);
	BN_hex2bn(&pbs->g, hexg);

	if ((pbs->p == NULL) || (pbs->q == NULL) || (pbs->g == NULL)) {
		ERROR("problem loading params: one of p, q, g is null");
		BN_free(pbs->p);
		BN_free(pbs->q);
		BN_free(pbs->g);
		return ERR;
	}
	return SCS;
}

void free_parameters(pbs_parameters *pbs) {
	INFO("Freeing BIGNUM values from parameters");
	if (pbs != NULL) {
		BN_clear_free(pbs->p);
		BN_clear_free(pbs->q);
		BN_clear_free(pbs->g);
	}
	INFO("Finished freeing BIGNUM values");
}

int gen_keys(pbs_parameters *pbs, pbs_sk *sk, pbs_pk *pk) {
	BN_CTX *ctx = NULL;

	sk->x = BN_new();
	pk->y = BN_new();
	ctx = BN_CTX_new();

	/* check if any of the BN creations had an error */
	if (sk->x == NULL || pk->y == NULL || ctx == NULL) {
		WARNING("BN_new or BN_CTX_new error");
		goto err;
	}

	INFO("generate random secret integer x, 1 <= x <= (q-1)");
	if (!get_random_mod(sk->x, pbs->q)) {
		WARNING("get_random error");
		goto err;
	}

	INFO("generate public integer y = g^x mod p");
	if (!BN_mod_exp(pk->y, pbs->g, sk->x, pbs->p, ctx)) {
		WARNING("BN_mod_exp error");
		goto err;
	}

	/* free temp BIGNUMS */
	BN_CTX_free(ctx);

	INFO("key generation completed!");
	return SCS;

	err: free_keys(sk, pk);
	BN_CTX_free(ctx);
	ERROR("BIGNUMS freed, aborting now!");
	return ERR;
}

int load_keys(pbs_sk *sk, pbs_pk *pk) {
	sk->x = BN_new();
	pk->y = BN_new();

	BN_hex2bn(&sk->x, hexx);
	BN_hex2bn(&pk->y, hexy);

	if ((sk->x == NULL) || (pk->y == NULL)) {
		ERROR("problem loading params: one of x, y is null");
		BN_free(sk->x);
		BN_free(pk->y);
		return ERR;
	}
	return SCS;
}

void free_keys(pbs_sk *sk, pbs_pk *pk) {
	INFO("Freeing BIGNUM values from keys");
	if (pk != NULL) {
		BN_clear_free(pk->y);
	}
	if (sk != NULL) {
		BN_clear_free(sk->x);
	}
	INFO("Finished freeing BIGNUM values");
}

int get_random_mod(BIGNUM *result, BIGNUM *mod) {
	BIGNUM *x_range = NULL;
	x_range = BN_new();

	/* check if any of the BN creations had an error */
	if (x_range == NULL) {
		WARNING("BN_new error");
		goto err;
	}

	/* we will select result in 0 <= result <= (mod-2) first, and then add 1 to result
	 * (b/c of the BN_pseudo_rand_range function)*/
	if (!BN_sub(x_range, mod, BN_value_one())) {
		WARNING("BN_sub error");
		goto err;
	}
	/* FIXME do we need to seed the PNRG with RAND_seed or equivalent?*/
	/* generates 0 <= a < a_range = q - 1 */
	if (!BN_rand_range(result, x_range)) {
		WARNING("BN_pseudo_rand_range error");
		goto err;
	}
	/* x = x + 1 , x will be in range 1 <= x <= x_range = q - 1*/
	if (!BN_add(result, result, BN_value_one())) {
		WARNING("BN_add error");
		goto err;
	}
	BN_clear_free(x_range);
	return SCS;

	err: BN_clear_free(x_range);
	return ERR;
}

void printBN(BIGNUM *bn, char *msg) {
	fprintf(stdout, "%s", msg);
	fprintf(stdout, BN_bn2hex(bn), msg);
	fprintf(stdout, "\n");
}

int hash_mod(BIGNUM *result, char *info, BIGNUM *mod) {
	/* the H hash in Abe&Okamoto;  H: {0,1}* -> Z_q */
	BIGNUM *hash = NULL;
	BN_CTX *ctx = NULL;
	unsigned char *out;

	/* temporary space to hold the binary result of the hash */
	out = calloc(20, sizeof(unsigned char));
	/* do the hash(info) operation */
	SHA1((unsigned char*) info, strlen(info), out);
	/* convert the hash to a BIGNUM */
	hash = BN_bin2bn(out, 20, NULL);
	/* free the temporary space */
	free(out);

	ctx = BN_CTX_new();
	if (ctx == NULL) {
		INFO("BN_new or BN_CTX_new error");
		return ERR;
	}

	/* do the mod q operation */
	if (!BN_mod(result, hash, mod, ctx)) {
		goto err;
	}
	BN_CTX_free(ctx);
	BN_free(hash);
	return SCS;

	err: BN_free(hash);
	BN_CTX_free(ctx);
	INFO("Error in hash_mod");
	return ERR;
}

int hash_group(BIGNUM *result, char *info, pbs_parameters *pbs) {
	/* the F hash in Abe&Okamoto;  F: {0,1}* -> <g> */
	BIGNUM *remainder = NULL;
	BN_CTX *ctx = NULL;

	/* will hold result of the hash_mod operation */
	remainder = BN_new();
	if (remainder == NULL) {
		INFO("BN_new error");
		goto err;
	}

	/* do: hash(info) mod q */
	if (hash_mod(remainder, info, pbs->q)) {
		/* if successful we want to make sure it maps to element of group <g> */
		ctx = BN_CTX_new();
		if (ctx == NULL) {
			INFO("BN_CTX_new error");
			goto err;
		}
		/* generate element of group <g> */
		if (!BN_mod_exp(result, pbs->g, remainder, pbs->p, ctx)) {
			INFO("Unsuccessful BN_mod_exp");
			goto err;
		}
	} else {
		goto err;
	}

	INFO("Successful hash_group");
	BN_CTX_free(ctx);
	BN_free(remainder);
	return SCS;

	err: BN_CTX_free(ctx);
	BN_free(remainder);
	INFO("Error in hash_group");
	return ERR;
}

int bank_sign_init(BIGNUM *a, BIGNUM *b, pbs_bank_state *state, char *info,
		pbs_parameters *pbs) {
	BIGNUM *z = NULL;
	BN_CTX *ctx;

	state->d = BN_new();
	state->u = BN_new();
	state->s = BN_new();
	z = BN_new();
	ctx = BN_CTX_new();

	/* check if any of the BN creations had an error */
	if (state->d == NULL || state->u == NULL || state->s == NULL || z == NULL) {
		WARNING("BN_new or BN_CTX_new error");
		goto err;
	}

	if (!get_random_mod(state->u, pbs->q) || !get_random_mod(state->s, pbs->q)
			|| !get_random_mod(state->d, pbs->q)) {
		goto err;
	}
	if (!hash_group(z, info, pbs)) {
		goto err;
	}

	/* a is used as temp variable to compute b */
	if (!BN_mod_exp(a, pbs->g, state->s, pbs->p, ctx)) {
		goto err;
	}
	if (!BN_mod_exp(b, z, state->d, pbs->p, ctx)) {
		goto err;
	}
	if (!BN_mod_mul(b, a, b, pbs->p, ctx)) {
		goto err;
	}

	/* compute the real a value */
	if (!BN_mod_exp(a, pbs->g, state->u, pbs->p, ctx)) {
		goto err;
	}

	BN_CTX_free(ctx);
	BN_free(z);
	return SCS;

	err: BN_CTX_free(ctx);
	BN_free(z);
	ERROR("Error in bank_sign_init");
	return ERR;
}

int bank_sign_update(BIGNUM *r, BIGNUM *c, BIGNUM *s, BIGNUM *d,
		pbs_bank_state *state, pbs_parameters *pbs, pbs_sk *sk, BIGNUM *e) {
	BN_CTX *ctx = NULL;
	ctx = BN_CTX_new();

	/* check if any of the BN creations had an error */
	if (ctx == NULL) {
		goto err;
	}

	if (!BN_mod_sub(c, e, state->d, pbs->q, ctx)) {
		goto err;
	}
	/* use s as temp variable */
	if (!BN_mod_mul(s, c, sk->x, pbs->q, ctx)) {
		goto err;
	}
	if (!BN_mod_sub(r, state->u, s, pbs->q, ctx)) {
		goto err;
	}
	if (BN_copy(s, state->s) == NULL || BN_copy(d, state->d) == NULL) {
		goto err;
	}

	BN_CTX_free(ctx);
	return SCS;

	err: BN_CTX_free(ctx);
	ERROR("Error in sign_final");
	return ERR;
}

int sign_init(pbs_client_state *state, pbs_signature *signature,
		pbs_workspace *workspace) {
	state->t1 = BN_new();
	state->t2 = BN_new();
	state->t3 = BN_new();
	state->t4 = BN_new();
	state->epsilon = BN_new();
	signature->delta = BN_new();
	signature->rho = BN_new();
	signature->omega = BN_new();
	signature->sigma = BN_new();

	workspace->left = BN_new();
	workspace->right = BN_new();
	workspace->temp1 = BN_new();
	workspace->z = BN_new();
	workspace->ctx = BN_CTX_new();

	/* check if any of the BN creations had an error */
	if (workspace->z == NULL || workspace->left == NULL || workspace->right
			== NULL || workspace->temp1 == NULL || workspace->ctx == NULL) {
		goto err;
	}

	/* check if any of the BN creations had an error */
	if (state->t1 == NULL || state->t2 == NULL || state->t3 == NULL
			|| state->t4 == NULL || state->epsilon == NULL || signature->rho
			== NULL || signature->sigma == NULL || signature->delta == NULL
			|| signature->omega == NULL) {
		goto err;
	}

	/* send message to bank requesting a, b values (use a,b values from cache?)*/

	return SCS;

	err: BN_free(state->epsilon);
	BN_free(state->t1);
	BN_free(state->t2);
	BN_free(state->t3);
	BN_free(state->t4);
	BN_free(signature->rho);
	BN_free(signature->sigma);
	BN_free(signature->delta);
	BN_free(signature->omega);
	BN_free(workspace->left);
	BN_free(workspace->right);
	BN_free(workspace->temp1);
	BN_free(workspace->z);
	BN_CTX_free(workspace->ctx);
	ERROR("Error in sign_init");
	return ERR;
}

int sign_update(BIGNUM *e, pbs_client_state *state, pbs_parameters *pbs,
		pbs_pk *pk, char *message, char *info, BIGNUM *a, BIGNUM *b) {
	BIGNUM *alpha = NULL;
	BIGNUM *beta = NULL;
	BIGNUM *z = NULL;
	BN_CTX *ctx = NULL;

	alpha = BN_new();
	beta = BN_new();
	z = BN_new();
	ctx = BN_CTX_new();

	/* check if any of the BN creations had an error */
	if (alpha == NULL || beta == NULL || z == NULL || ctx == NULL) {
		goto err;
	}

	if (!get_random_mod(state->t1, pbs->q)
			|| !get_random_mod(state->t2, pbs->q) || !get_random_mod(state->t3,
			pbs->q) || !get_random_mod(state->t4, pbs->q)) {
		goto err;
	}
	if (!hash_group(z, info, pbs)) {
		goto err;
	}

	/* Compute alpha - use epsilon as a temp variable for now */
	if (!BN_mod_exp(state->epsilon, pbs->g, state->t1, pbs->p, ctx)) {
		goto err;
	}
	if (!BN_mod_mul(alpha, a, state->epsilon, pbs->p, ctx)) {
		goto err;
	}
	if (!BN_mod_exp(state->epsilon, pk->y, state->t2, pbs->p, ctx)) {
		goto err;
	}
	if (!BN_mod_mul(alpha, alpha, state->epsilon, pbs->p, ctx)) {
		goto err;
	}

	/* Compute beta - use epsilon as a temp variable for now */
	if (!BN_mod_exp(state->epsilon, pbs->g, state->t3, pbs->p, ctx)) {
		goto err;
	}
	if (!BN_mod_mul(beta, b, state->epsilon, pbs->p, ctx)) {
		goto err;
	}
	if (!BN_mod_exp(state->epsilon, z, state->t4, pbs->p, ctx)) {
		goto err;
	}
	if (!BN_mod_mul(beta, beta, state->epsilon, pbs->p, ctx)) {
		goto err;
	}

	/* compute epsilon */
	int buffer_len = BN_num_bytes(alpha) + BN_num_bytes(beta) + BN_num_bytes(z)
			+ strlen(message) + 1;
	char *buffer = calloc(1, buffer_len);
	char *pos = buffer;
	BN_bn2bin(alpha, (unsigned char*) buffer);
	pos = pos + BN_num_bytes(alpha);
	BN_bn2bin(beta, (unsigned char*) pos);
	pos = pos + BN_num_bytes(beta);
	BN_bn2bin(z, (unsigned char*) pos);
	pos = pos + BN_num_bytes(z);
	memcpy(pos, message, strlen(message));

	int success = hash_mod(state->epsilon, buffer, pbs->q);
	free(buffer);
	if (!success) {
		goto err;
	}

	/* compute e */
	if (!BN_mod_sub(e, state->epsilon, state->t2, pbs->q, ctx)) {
		goto err;
	}
	if (!BN_mod_sub(e, e, state->t4, pbs->q, ctx)) {
		goto err;
	}

	BN_free(z);
	BN_free(alpha);
	BN_free(beta);
	BN_CTX_free(ctx);
	return SCS;

	err: BN_free(z);
	BN_free(alpha);
	BN_free(beta);
	BN_CTX_free(ctx);
	BN_free(e);
	ERROR("Error in sign_update");
	return ERR;
}

int sign_final(pbs_signature *signature, BIGNUM *r, BIGNUM *c, BIGNUM *s,
		BIGNUM *d, pbs_client_state *state, pbs_parameters *pbs) {
	BN_CTX *ctx = NULL;
	BIGNUM *check = NULL;
	check = BN_new();
	ctx = BN_CTX_new();

	/* check if any of the BN creations had an error */
	if (check == NULL || ctx == NULL) {
		goto err;
	}

	if (!BN_mod_add(signature->rho, r, state->t1, pbs->q, ctx) || !BN_mod_add(
			signature->omega, c, state->t2, pbs->q, ctx) || !BN_mod_add(
			signature->sigma, s, state->t3, pbs->q, ctx) || !BN_mod_add(
			signature->delta, d, state->t4, pbs->q, ctx)) {
		goto err;
	}

	/* do internal consistency check */
	if (!BN_mod_add(check, signature->omega, signature->delta, pbs->q, ctx)) {
		goto err;
	}
	if (BN_cmp(check, state->epsilon) != 0) {
		WARNING("Internal Consistency Check Failure!");
	}

	BN_CTX_free(ctx);
	BN_free(check);
	return SCS;

	err: BN_CTX_free(ctx);
	BN_free(check);
	ERROR("Error in sign_final");
	return ERR;
}

int verify(pbs_signature *signature, pbs_pk *pk, pbs_parameters *pbs,
		char *info, char *message, pbs_workspace *workspace) {
	/* verify: omega+delta =? H(g^rho * y^omega | g^sigma * F(info)^delta || F(info) || msg) */
	int success = 0;

	/* compute right side (the hash) */

	/* left = g^(rho) * y^(omega) mod p*/
	if (!BN_mod_exp(workspace->left, pbs->g, signature->rho, pbs->p, workspace->ctx) || !BN_mod_exp(
			workspace->right, pk->y, signature->omega, pbs->p, workspace->ctx)) {
		goto err;
	}
	if (!BN_mod_mul(workspace->left, workspace->left, workspace->right, pbs->p, workspace->ctx)) {
		goto err;
	}

	/* z = F(info) */
	if (!hash_group(workspace->z, info, pbs)) {
		goto err;
	}

	/* right = g^{sigma) * z^(delta) mod p */
	if (!BN_mod_exp(workspace->right, pbs->g, signature->sigma, pbs->p, workspace->ctx)
			|| !BN_mod_exp(workspace->temp1, workspace->z, signature->delta, pbs->p, workspace->ctx)) {
		goto err;
	}
	if (!BN_mod_mul(workspace->right, workspace->right, workspace->temp1, pbs->p, workspace->ctx)) {
		goto err;
	}

	/* we now want H(left|right|z|message) (this is mod q)*/
	int buffer_len = BN_num_bytes(workspace->left) + BN_num_bytes(workspace->right) + BN_num_bytes(workspace->z)
			+ strlen(message) + 1;
	char *buffer = calloc(1, buffer_len);
	char *pos = buffer;
	BN_bn2bin(workspace->left, (unsigned char*) buffer);
	pos = pos + BN_num_bytes(workspace->left);
	BN_bn2bin(workspace->right, (unsigned char*) pos);
	pos = pos + BN_num_bytes(workspace->right);
	BN_bn2bin(workspace->z, (unsigned char*) pos);
	pos = pos + BN_num_bytes(workspace->z);
	memcpy(pos, message, strlen(message));

	success = hash_mod(workspace->right, buffer, pbs->q);
	free(buffer);
	if (!success) {
		goto err;
	}

	/* left = (omega + delta) mod q*/
	if (!BN_mod_add(workspace->left, signature->omega, signature->delta, pbs->q, workspace->ctx)) {
		goto err;
	}

	/* BN_cmp returns 0 if they are equal */
	success = BN_cmp(workspace->left, workspace->right) == 0;

	return success;
err:
	ERROR("Error in verify");
	return ERR;
}

void free_signature(pbs_signature *signature) {
	INFO("Freeing BIGNUM values from signature");
	if (signature != NULL) {
		BN_clear_free(signature->delta);
		BN_clear_free(signature->omega);
		BN_clear_free(signature->rho);
		BN_clear_free(signature->sigma);
	}
	INFO("Finished freeing BIGNUM values");
}

void free_bank_state(pbs_bank_state *state) {
	INFO("Freeing BIGNUM values from signature");
	if (state != NULL) {
		BN_clear_free(state->d);
		BN_clear_free(state->s);
		BN_clear_free(state->u);
	}
	INFO("Finished freeing BIGNUM values");
}

void free_client_state(pbs_client_state *state) {
	INFO("Freeing BIGNUM values from signature");
	if (state != NULL) {
		BN_clear_free(state->t1);
		BN_clear_free(state->t2);
		BN_clear_free(state->t3);
		BN_clear_free(state->t4);
		BN_clear_free(state->epsilon);
	}
	INFO("Finished freeing BIGNUM values");
}

void free_workspace(pbs_workspace *workspace) {
	INFO("Freeing BIGNUM values from signature");
	if (workspace != NULL) {
		BN_free(workspace->left);
		BN_free(workspace->right);
		BN_free(workspace->temp1);
		BN_free(workspace->z);
		BN_CTX_free(workspace->ctx);
	}
	INFO("Finished freeing BIGNUM values");
}
