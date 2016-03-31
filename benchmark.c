/*
 * benchmark.c
 *
 *  Created on: Feb 20, 2010
 *      Author: rob
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/aes.h>
#include <sys/time.h>
#include <time.h>

#include "pbs.h"
#include "mcl_ecpbs_common.h"
#include "mcl_ecpbs_client.h"
#include "mcl_ecpbs_bank.h"
#include "gmp_pbs_common.h"
#include "gmp_pbs_client.h"
#include "gmp_pbs_bank.h"

#define CELL_NETWORK_SIZE 512
#define BYTES_PER_GB 1073741824 // bytes to allocate during teh experiment = 1gb
#define CELLS_PER_GB (BYTES_PER_GB/CELL_NETWORK_SIZE)
#define TICKETS_PER_GB (BYTES_PER_GB/(32*1024))

#define NUM_RUNS 1
#define NUM_LOOPS_PER_RUN CELLS_PER_GB

long get_timer_nanos(struct timespec *start, struct timespec *end){
	return (end->tv_sec - start->tv_sec) * 1000000000 + (end->tv_nsec - start->tv_nsec);
}

void pbs_test(char *data) {
	pbs_parameters pbs;
	pbs_pk pk;
	pbs_sk sk;
	pbs_bank_state bstate;
	pbs_client_state cstate;
	pbs_signature signature;
	pbs_workspace workspace;
	struct timespec bank_start, bank_end, verify_start, verify_end;
	long bank_nanos = 0;
	long verify_nanos = 0;
	int success, i = 0;

	load_parameters(&pbs);
	/* use this to generate keys */
	/*
	 gen_keys(&pbs, &sk, &pk);
	 printf("skx:%s\n", BN_bn2hex(sk.x));
	 printf("pky:%s\n", BN_bn2hex(pk.y));
	 */
	load_keys(&sk, &pk);

	int date1 = time(NULL) / 86400;
	int date2 = date1 + 7;
	int date3 = date1 + 28;
	int infolen = 3 * sizeof(date1) + 6; /* 3 ints, 2 commas, null byte */
	char info[infolen];
	snprintf(info, infolen, "%d,%d,%d", date1, date2, date3);
	/* printf("%s\n", info); */

	/* do a bunch of signatures and verifies */
	/* FIXME this can be made much more efficient */
	char *pos = data;
	for (i = 0; i < NUM_LOOPS_PER_RUN; ++i) {
		BIGNUM *a = BN_new();
		BIGNUM *b = BN_new();
		BIGNUM *e = BN_new();
		BIGNUM *r = BN_new();
		BIGNUM *c = BN_new();
		BIGNUM *s = BN_new();
		BIGNUM *d = BN_new();

		/* client sends bank request, bank sends back a,b,info */
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &bank_start);
		bank_sign_init(a, b, &bstate, info, &pbs);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &bank_end);

		bank_nanos = get_timer_nanos(&bank_start, &bank_end);

		/* client initialization */
		sign_init(&cstate, &signature, &workspace);
		/* client uses a,b,info and its message to produce e for bank */
		sign_update(e, &cstate, &pbs, &pk, data, info, a, b);

		/* bank uses e to produce r,c,s,d for client */
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &bank_start);
		bank_sign_update(r, c, s, d, &bstate, &pbs, &sk, e);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &bank_end);

		bank_nanos += get_timer_nanos(&bank_start, &bank_end);

		/* client finishes signature */
		sign_final(&signature, r, c, s, d, &cstate, &pbs);

		/* now verify */
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &verify_start);
		success = verify(&signature, &pk, &pbs, info, data, &workspace);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &verify_end);

		verify_nanos = get_timer_nanos(&verify_start, &verify_end);

		if (success != 0) {
			printf("Signature incorrect\n");
		}
		pos += CELL_NETWORK_SIZE + 1;

		BN_free(a);
		BN_free(b);
		BN_free(e);
		BN_free(r);
		BN_free(c);
		BN_free(s);
		BN_free(d);
		free_bank_state(&bstate);
		free_client_state(&cstate);
		free_signature(&signature);
		free_workspace(&workspace);

		printf("pbs Bank effort: 1 signature %ld nanoseconds (%d/%d)\n", bank_nanos, i+1, NUM_LOOPS_PER_RUN);
		printf("pbs Signature verification: 1 verify %ld nanoseconds (%d/%d)\n", verify_nanos, i+1, NUM_LOOPS_PER_RUN);
	}

	free_keys(&sk, &pk);
	free_parameters(&pbs);


#ifdef DEBUG
	/* signature results */
	printBN(signature.delta, "delta:");
	printBN(signature.sigma, "sigma:");
	printBN(signature.omega, "omega:");
	printBN(signature.rho, "rho:");
	printf("info:%s\n", info);
	printf("message:%s\n", message);

	printBN(a, "a:");
	printBN(b, "b:");
	printBN(e, "e:");
	printBN(r, "r:");
	printBN(c, "c:");
	printBN(s, "s:");
	printBN(d, "d:");
	printBN(cstate.t1, "t1:");
	printBN(cstate.t2, "t2:");
	printBN(cstate.t3, "t3:");
	printBN(cstate.t4, "t4:");
	printBN(cstate.epsilon, "epsilon:");
	printBN(bstate.d, "d:");
	printBN(bstate.s, "s:");
	printBN(bstate.u, "u:");
	printBN(pbs.g, "g:");
	printBN(pbs.p, "p:");
	printBN(pbs.q, "q:");
	printBN(pk.y, "y:");
	printBN(sk.x, "x:");

	/* sanity checks */
	BIGNUM *temp1 = BN_new();
	BIGNUM *temp2 = BN_new();
	BN_CTX *ctx = BN_CTX_new();

	/* q |? p-1 */
	BN_sub(temp1, pbs.p, BN_value_one());
	BN_mod(temp2, temp1, pbs.q, ctx);
	printf("q|p-1 remainder: %s\n", BN_bn2hex(temp2));

	/* g^q =? 1 mod p */
	BN_mod_exp(temp1, pbs.g, pbs.q, pbs.p, ctx);
	printf("g^q =? 1 mod p result: %s\n", BN_bn2hex(temp1));
#endif

	/*
	 BN_free(a);
	 BN_free(b);
	 BN_free(e);
	 BN_free(r);
	 BN_free(c);
	 BN_free(s);
	 BN_free(d);
	 free_bank_state(&bstate);
	 free_client_state(&cstate);
	 free_signature(&signature);
	 free_keys(&sk, &pk);
	 free_parameters(&pbs);
	 */
}

void mcl_ecpbs_test(char *data) {
	/* timing the experiment */
	struct timespec bank_start, bank_end, verify_start, verify_end;
	long bank_nanos = 0;
	long verify_nanos = 0;
	int i = 0;
	int result = 0;

	/* simulate client and bank interaction */
	mcl_ecpbs_bank_state bstate;
	mcl_ecpbs_state cstate;

	mcl_ecpbs_init_bank(&bstate);
	mcl_ecpbs_init(&cstate);

	int date1 = time(NULL) / 86400;
	int date2 = date1 + 7;
	int date3 = date1 + 28;
	int infolen = 3 * sizeof(date1) + 6; /* 3 ints, 2 commas, null byte */
	char info[infolen];
	snprintf(info, infolen, "%d,%d,%d", date1, date2, date3);

	/* do a bunch of signatures and verifies */
	char *pos = data;
	for (i = 0; i < NUM_LOOPS_PER_RUN; ++i) {

		/* bank computes a,b */
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &bank_start);
		mcl_ecpbs_sign_start_bank(&bstate, info);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &bank_end);

		bank_nanos = get_timer_nanos(&bank_start, &bank_end);

		/* bank 'sends' a,b,info to client */
		epoint_copy(bstate.a, cstate.a);
		epoint_copy(bstate.b, cstate.b);

		/* client computes e */
		mcl_ecpbs_sign_start(&cstate, info, pos);

		/* client 'sends' e to bank */
		copy(cstate.e, bstate.e);

		/* bank produces r,c,s,d for client */
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &bank_start);
		mcl_ecpbs_sign_finish_bank(&bstate);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &bank_end);

		bank_nanos += get_timer_nanos(&bank_start, &bank_end);

		/* bank 'sends' r,c,s,d to client */
		copy(bstate.r, cstate.r);
		copy(bstate.c, cstate.c);
		copy(bstate.s, cstate.s);
		copy(bstate.d, cstate.d);

		/* client finishes signature */
		if (!mcl_ecpbs_sign_finish(&cstate)) {
			printf("Signature consistency check failed\n");
		}

		/* now verify */
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &verify_start);
		result = mcl_ecpbs_verify(&cstate.signature, info, pos,
				&cstate.parameters, &cstate.pk, &cstate.workspace);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &verify_end);

		verify_nanos = get_timer_nanos(&verify_start, &verify_end);

		if (result != 0) {
			printf("Signature incorrect\n");
			mcl_ecpbs_print_bank(&bstate, stdout);
			mcl_ecpbs_print(&cstate, stdout);
		}

		pos += CELL_NETWORK_SIZE + 1;

		mcl_ecpbs_reset_bank(&bstate);
		mcl_ecpbs_reset(&cstate);

		printf("mcl_ecpbs Bank effort: 1 signature %ld nanoseconds (%d/%d)\n", bank_nanos, i+1, NUM_LOOPS_PER_RUN);
		printf("mcl_ecpbs Signature verification: 1 verify %ld nanoseconds (%d/%d)\n", verify_nanos, i+1, NUM_LOOPS_PER_RUN);
	}

	/* free state and miracl */
	mcl_ecpbs_free_bank(&bstate);
	mcl_ecpbs_free(&cstate);
	mirexit();
}

void gmp_pbs_test(char *data) {
	/* timing the experiment */
	struct timespec bank_start, bank_end, verify_start, verify_end;
	long bank_nanos = 0;
	long verify_nanos = 0;
	int i = 0;
	int result = 0;

	/* simulate client and bank interaction */
	gmp_pbs_bank_state bstate;
	gmp_pbs_client_state cstate;

	gmp_pbs_bank_init(&bstate);
	gmp_pbs_client_init(&cstate);

	int date1 = time(NULL) / 86400;
	int date2 = date1 + 7;
	int date3 = date1 + 28;
	int infolen = 3 * sizeof(date1) + 6; /* 3 ints, 2 commas, null byte */
	char info[infolen];
	snprintf(info, infolen, "%d,%d,%d", date1, date2, date3);

	/* do a bunch of signatures and verifies */
	char *pos = data;
	for (i = 0; i < NUM_LOOPS_PER_RUN; ++i) {

		/* bank computes a,b */
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &bank_start);
		gmp_pbs_bank_sign_start(&bstate, info);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &bank_end);

		bank_nanos = get_timer_nanos(&bank_start, &bank_end);

		/* bank 'sends' a,b,info to client */
		mpz_set(cstate.a, bstate.a);
		mpz_set(cstate.b, bstate.b);

		/* client computes e */
		gmp_pbs_client_sign_start(&cstate, info, pos);

		/* client 'sends' e to bank */
		mpz_set(bstate.e, cstate.e);

		/* bank produces r,c,s,d for client */
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &bank_start);
		gmp_pbs_bank_sign_finish(&bstate);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &bank_end);

		bank_nanos += get_timer_nanos(&bank_start, &bank_end);

		/* bank 'sends' r,c,s,d to client */
		mpz_set(cstate.r, bstate.r);
		mpz_set(cstate.c, bstate.c);
		mpz_set(cstate.s, bstate.s);
		mpz_set(cstate.d, bstate.d);

		/* client finishes signature */
		if (gmp_pbs_client_sign_finish(&cstate) != 0) {
			printf("Signature consistency check failed\n");
		}

		/* now verify */
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &verify_start);
		result = gmp_pbs_verify(&cstate.signature, info, pos,
				&cstate.parameters, &cstate.pk, &cstate.workspace);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &verify_end);

		verify_nanos = get_timer_nanos(&verify_start, &verify_end);

		if (result != 0) {
			printf("Signature incorrect\n");
			gmp_pbs_client_print(&cstate, stdout);
			gmp_pbs_bank_print(&bstate, stdout);
			exit(0);
		}

		pos += CELL_NETWORK_SIZE + 1;

		gmp_pbs_bank_reset(&bstate);
		gmp_pbs_client_reset(&cstate);

		printf("gmp_pbs Bank effort: 1 signature %ld nanoseconds (%d/%d)\n", bank_nanos, i+1, NUM_LOOPS_PER_RUN);
		printf("gmp_pbs Signature verification: 1 verify %ld nanoseconds (%d/%d)\n", verify_nanos, i+1, NUM_LOOPS_PER_RUN);
	}

	/* free state */
	gmp_pbs_bank_free(&bstate);
	gmp_pbs_client_free(&cstate);
}

int main(int argc, char *argv[]) {
	int i = 0;
	for (i = 0; i < NUM_RUNS; ++i) {
		time_t t;
		time(&t);
		printf(ctime(&t));
		printf("Running...\n");
		/*
		 * 1 gigabyte = 1073741824 bytes = 2097152 (512-byte) cells
		 * Cell payload = 509 bytes
		 */
		/* 0 byte between each cell, and extra cell at the end for the final crypt */
		char *data = calloc(1, (CELL_NETWORK_SIZE + 1) * (CELLS_PER_GB));
		memset(data, 'z', CELL_NETWORK_SIZE); /* payload in first cell */

		/* Timings for the bank and the verify functionalities. */

        /* OpenSSL version */
		pbs_test(data);

		/* miracl elliptic curve version */
		mcl_ecpbs_test(data);

		/* gmp version */
		gmp_pbs_test(data);

		free(data);
		printf("Done!\n");
	}

	return 0;
}
