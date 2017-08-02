/*
 * File: myGMP.c
 * Implements client-side cryptographic functions necessary for secure file
 * comparison. Part of 2017 REU in secure cloud computing at MST.
 * Written by Samuel Li
 */

#include "myGMP.h"
#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>

static const int BASE = 10;
static const int PK_NUM_ELEMENTS = 5;

enum {G, N, N_SQUARED, TOTIENT, MU};

static void encrypt(mpz_t message, mpz_t ciphertext, mpz_t pk[]);
static void decrypt(mpz_t plaintext, mpz_t ciphertext, mpz_t pk[]);

/* Helper function to decrypt Paillier-ciphertext*/
void specialTotient(mpz_t totient, mpz_t p, mpz_t q) {

    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(totient, p, q);
    mpz_add_ui(p, p, 1);
    mpz_add_ui(q, q, 1);
}

/* Creates public Paillier key of size numBits */
JNIEXPORT jobjectArray JNICALL Java_ClientCommunication_initialize
  (JNIEnv *env, jobject obj, jint numBits) {
    
    int bit_size = (int) numBits;
    
    mpz_t p, q, g, n, n_squared, totient, mu;
    mpz_inits(p, q, g, n, n_squared, totient, mu, NULL);
    
    // sets up random number generator
    gmp_randstate_t r_state;
    gmp_randinit_default(r_state);
    srand(time(NULL));
    int random = rand();
    gmp_randseed_ui(r_state, random);
    
    // calculates prime numbers p, q
    mpz_urandomb(p, r_state, bit_size);
    mpz_urandomb(q, r_state, bit_size);
    mpz_nextprime(p, p);
    mpz_nextprime(q, q);
    
    // calculates n and g
    mpz_mul(n, p, q);
    mpz_add_ui(g, n, 1);
    
    // calculate n_squared
    mpz_mul(n_squared, n, n);
    
    // calculate the totient
    specialTotient(totient, p, q);
    
    // calculates mu
    int success;
    success = mpz_invert(mu, totient, n);
    if (success) {
        printf("Mu calculation successful\n");
        fflush(stdout);
    }
    
    mpz_t pkMPZ[PK_NUM_ELEMENTS];
    for (int i = 0; i < PK_NUM_ELEMENTS; i++)
        mpz_init(pkMPZ[i]);
    
    mpz_set(pkMPZ[G], g);
    mpz_set(pkMPZ[N], n);
    mpz_set(pkMPZ[N_SQUARED], n_squared);
    mpz_set(pkMPZ[TOTIENT], totient);
    mpz_set(pkMPZ[MU], mu);
    
    // testing code
//    gmp_printf("p: %Zd\n", p);
//    gmp_printf("q: %Zd\n", q);
//    gmp_printf("g: %Zd\n", g);
//    gmp_printf("n: %Zd\n", n);
//    gmp_printf("n_squared: %Zd\n", n_squared);
//    gmp_printf("totient: %Zd\n", totient);
//    gmp_printf("mu: %Zd\n", mu);
//    fflush(stdout);
    
    jobjectArray pk;
    
    // initializes private key String array
    pk = (*env)->NewObjectArray(env, PK_NUM_ELEMENTS, 
            (*env)->FindClass(env, "java/lang/String"),0);
    
    for (int i = 0; i < PK_NUM_ELEMENTS; i++) {
        // converts mpz_t to char*
        char *tempStringC = mpz_get_str(NULL, BASE, pkMPZ[i]);
        // converts char* to jstring
        jstring tempStringJava = (*env)->NewStringUTF(env, tempStringC);
        // stores jstring in String array
        (*env)->SetObjectArrayElement(env, pk, i, tempStringJava);
        // release resources
//        (*env)->ReleaseStringUTFChars(env, tempStringJava, tempStringC);
        free(tempStringC);
    }
    
    mpz_clears(p, q, g, n, n_squared, totient, mu, NULL);
    return pk;
}

/* Encrypts integer message with key pk by Paillier encryption scheme*/
JNIEXPORT jstring JNICALL Java_ClientCommunication_encrypt
  (JNIEnv *env, jobject obj, jint message, jobjectArray pk) {
    
    int m = (int) message;
    // converts message from jstring to c string
//    const char *messageStringC = (*env)->GetStringUTFChars(env, message, NULL);
    

    mpz_t ciphertext, tempNum, r, gRaisedm, rRaisedn, gcd;
    mpz_inits(ciphertext, tempNum, r, gRaisedm, rRaisedn, gcd, NULL);
    mpz_t pkMPZ[PK_NUM_ELEMENTS];
    
    for (int i = 0; i < PK_NUM_ELEMENTS; i++)
        mpz_init(pkMPZ[i]);
    
    // converts pk String array to mpz_t array
    for (int i = 0; i < PK_NUM_ELEMENTS; i++) {
        
        // convert string in pk to char*
        jobject objString = (*env)->GetObjectArrayElement(env, pk, i);
        jstring tempStringJava = (jstring) objString;
        const char *tempStringC = (*env)->GetStringUTFChars(env, tempStringJava, NULL);
        
        // convert char* to mpz_t, and place in mpz_t array
        mpz_set_str(tempNum, tempStringC, BASE);
        mpz_set(pkMPZ[i], tempNum);
        
        // release resources
        (*env)->ReleaseStringUTFChars(env, tempStringJava, tempStringC);
    }
    
    // sets up random number generator
    gmp_randstate_t r_state;
    gmp_randinit_default(r_state);
    srand(time(NULL));
    int random = rand();
    gmp_randseed_ui(r_state, random);
    
    gmp_randseed_ui(r_state, 12345);
    
    // generate r;
    int success, r_generated;
    r_generated = 0;
    while(!r_generated) {
        // generates potential r
        mpz_urandomm(r, r_state, pkMPZ[N]);
        mpz_gcd(gcd, r, pkMPZ[N]);
        success = mpz_cmp_ui(gcd, 1);
        // we want mpz_cmp_ui() to return 0
        if (!success) r_generated = 1;
    }
    
    
    // calculate g^m
    mpz_powm_ui(gRaisedm, pkMPZ[G], m, pkMPZ[N_SQUARED]);
    
    // calculate r^n
    mpz_powm(rRaisedn, r, pkMPZ[N], pkMPZ[N_SQUARED]);

    // calculate (g^m)(r^n)(modn^2)
    mpz_mul(ciphertext, gRaisedm, rRaisedn);
    mpz_mod(ciphertext, ciphertext, pkMPZ[N_SQUARED]);
    
    // converts ciphertext to java string
    char* ciphertextStringC = mpz_get_str(NULL, BASE, ciphertext);
    jstring ciphertextStringJava = (*env)->NewStringUTF(env, ciphertextStringC);
    
    free(ciphertextStringC);
    
    // clears mpz_t array
    for (int i = 0; i < PK_NUM_ELEMENTS; i++)
        mpz_clear(pkMPZ[i]);
    mpz_clears(ciphertext, tempNum, r, gRaisedm, rRaisedn, gcd, NULL);
    
    return ciphertextStringJava;
}

/* Decrypts ciphertext with private key pk*/
JNIEXPORT jint JNICALL Java_ClientCommunication_decrypt
  (JNIEnv *env, jobject obj, jstring ciphertext, jobjectArray pk) {
    
    int c = (int) ciphertext;
    
    mpz_t m, tempNum;
    mpz_inits(m, tempNum, NULL);
    mpz_t pkMPZ[PK_NUM_ELEMENTS];
    
    for (int i = 0; i < PK_NUM_ELEMENTS; i++)
        mpz_init(pkMPZ[i]);
    
    const char* ciphertextStringC = (*env)->GetStringUTFChars(env, ciphertext, NULL);
    
    int success = mpz_set_str(m, ciphertextStringC, BASE);
    if (success == -1)
        printf("Error converting string to number\n");
    
    // converts pk String array to mpz_t array
    for (int i = 0; i < PK_NUM_ELEMENTS; i++) {
        
        // convert string in pk to char*
        jobject objString = (*env)->GetObjectArrayElement(env, pk, i);
        jstring tempStringJava = (jstring) objString;
        const char *tempStringC = (*env)->GetStringUTFChars(env, tempStringJava, NULL);
        
        // convert char* to mpz_t, and place in mpz_t array
        mpz_set_str(tempNum, tempStringC, BASE);
        mpz_set(pkMPZ[i], tempNum);
        
        // release resources
        (*env)->ReleaseStringUTFChars(env, tempStringJava, tempStringC);
    }
    
    // computes c^totient (modn^2)
    mpz_powm(m, m, pkMPZ[TOTIENT], pkMPZ[N_SQUARED]);
    
    // computes L function
    mpz_sub_ui(m, m, 1);
    mpz_divexact(m, m, pkMPZ[N]);
    
    // computes 
    mpz_mul(m, m, pkMPZ[MU]);
    mpz_mod(m, m, pkMPZ[N]);
    
    int iMessage = mpz_get_ui(m);
    
    // release resources
    for (int i = 0; i < PK_NUM_ELEMENTS; i++)
        mpz_clear(pkMPZ[i]);
    mpz_clears(m, tempNum, NULL);
    (*env)->ReleaseStringUTFChars(env, ciphertext, ciphertextStringC);
    
    return iMessage;
}

/* SBIT protocol part two by Jiang et.al, not used in current application */
JNIEXPORT jstring JNICALL Java_ClientCommunication_SBITclient
  (JNIEnv *env, jobject obj, jstring YString, jobjectArray pk) {
    
    mpz_t Y, decryptedY, alpha, tempNum;
    mpz_inits(Y, decryptedY, alpha, tempNum, NULL);
    mpz_t pkMPZ[PK_NUM_ELEMENTS];
    
    for (int i = 0; i < PK_NUM_ELEMENTS; i++)
        mpz_init(pkMPZ[i]);
    
    // convert java string to c string
    const char* YStringC = (*env)->GetStringUTFChars(env, YString, NULL);
    
    // convert c string to mpz_t
    int success = mpz_set_str(Y, YStringC, BASE);
    if (success == -1)
        printf("Error converting string to number\n");
    
    // converts pk String array to mpz_t array
    for (int i = 0; i < PK_NUM_ELEMENTS; i++) {
        
        // convert string in pk to char*
        jobject objString = (*env)->GetObjectArrayElement(env, pk, i);
        jstring tempStringJava = (jstring) objString;
        const char *tempStringC = (*env)->GetStringUTFChars(env, tempStringJava, NULL);
        
        // convert char* to mpz_t, and place in mpz_t array
        mpz_set_str(tempNum, tempStringC, BASE);
        mpz_set(pkMPZ[i], tempNum);
        
        // release resources
        (*env)->ReleaseStringUTFChars(env, tempStringJava, tempStringC);
    }
    
    // decrypts Y
    decrypt(decryptedY, Y, pkMPZ);
    
    
    // if Y is even, alpha = E(0)
    if (mpz_even_p(decryptedY)) {
        mpz_set_ui(tempNum, 0);
        encrypt(tempNum, alpha, pkMPZ);
    }    
    // if Y is odd, alpha = E(1)
    else {
        mpz_set_ui(tempNum, 1);
        encrypt(tempNum, alpha, pkMPZ);
    }
    
    
    // convert alpha from mpz_t to jstring
    char *alphaCString = mpz_get_str(NULL, BASE, alpha);
    jstring alphaJavaString = (*env)->NewStringUTF(env, alphaCString);
    
    // releases resources
    for (int i = 0; i < PK_NUM_ELEMENTS; i++)
        mpz_clear(pkMPZ[i]);
    mpz_clears(Y, decryptedY, alpha, tempNum, NULL);
    (*env)->ReleaseStringUTFChars(env, YString, YStringC);
    free(alphaCString);
    
    return alphaJavaString;
}

/* helper function to decrypt ciphertext, store in plaintext, with pk */
static void decrypt(mpz_t plaintext, mpz_t ciphertext, mpz_t pk[]) {
	
    mpz_set(plaintext, ciphertext);
    
    // computes c^totient (modn^2)
    mpz_powm(plaintext, plaintext, pk[TOTIENT], pk[N_SQUARED]);
    
    // computes L function
    mpz_sub_ui(plaintext, plaintext, 1);
    mpz_divexact(plaintext, plaintext, pk[N]);
    
    // computes 
    mpz_mul(plaintext, plaintext, pk[MU]);
    mpz_mod(plaintext, plaintext, pk[N]);  
}
 
/* helper function to encrypt message, store in ciphertext, with key pk*/
static void encrypt(mpz_t message, mpz_t ciphertext, mpz_t pk[]) {

    mpz_t gRaisedm, rRaisedn, r, gcd;
    mpz_inits(gRaisedm, rRaisedn, r, gcd, NULL);
	
    // initialize r_state
    gmp_randstate_t r_state;
    gmp_randinit_default(r_state);
    srand(time(NULL));
    int random = rand();
    gmp_randseed_ui(r_state, random);
    
    // generates r
    // careful, different random function!
    int success;
    int r_generated = 0;
    while (!r_generated) {
            // generates potential r
            mpz_urandomm(r, r_state, pk[N]);
            mpz_gcd(gcd, r, pk[N]);
            success = mpz_cmp_ui(gcd, 1);
            // we want mpz_cmp_ui() to return 0
            if (!success)
                    r_generated = 1;
    }

    // calculates g^m
    mpz_powm(gRaisedm, pk[G], message, pk[N_SQUARED]);

    // calculates r^n
    mpz_powm(rRaisedn, r, pk[N], pk[N_SQUARED]);

    // multiply g^m by r^n
    mpz_mul(ciphertext, gRaisedm, rRaisedn);

    // mod the product by n^2
    mpz_mod(ciphertext, ciphertext, pk[N_SQUARED]);

    mpz_clears(gRaisedm, rRaisedn, r, gcd, NULL);
	
}