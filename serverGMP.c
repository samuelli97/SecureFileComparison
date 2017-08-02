/*
 * File: serverGMP.c
 * Implements server-side cryptographic functions necessary for secure file
 * comparison. Part of 2017 REU in secure cloud computing at MST.
 * Written by Samuel Li
 */

#include"serverGMP.h"
#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <jni.h>

static const int BASE = 10;

/* This JNI function employs homomorphic properties to calculate the product
 portion of the dot product. It calculates ciphertext^exponent = E(m * e),
 modulo nSquared*/
JNIEXPORT jstring JNICALL Java_ServerCommunication_GMPexponent
  (JNIEnv *env, jobject obj, jstring ciphertext, jint exponent, jstring nSquared) {
    
    // convert java strings to c strings
    const char *cipherString = (*env)->GetStringUTFChars(env, ciphertext, NULL);
    if (cipherString == NULL) return NULL;
    const char *nSquaredString = (*env)->GetStringUTFChars(env, nSquared, NULL);
    if (nSquaredString == NULL) return NULL;
    
    mpz_t cipherNum, modulus;
    mpz_inits(cipherNum, modulus, NULL);
    
    // set mpz_t variables from strings
    int success1, success2;
    success1 = mpz_set_str(cipherNum, cipherString, BASE);
    success2 = mpz_set_str(modulus, nSquaredString, BASE);
    if (success1 == -1 || success2 == -1)
        printf("Failed to convert string to number\n");
    
    // release resources
    (*env)->ReleaseStringUTFChars(env, ciphertext, cipherString);
    (*env)->ReleaseStringUTFChars(env, nSquared, nSquaredString);
    
    // computes exponent
    mpz_powm_ui(cipherNum, cipherNum, exponent, modulus);
    // converts mpz_t to c string, then to java string
    char *exponentStringC = mpz_get_str(NULL, 10, cipherNum);
    jstring exponentStringJava = (*env)->NewStringUTF(env, exponentStringC);
    
    // free memory
    free(exponentStringC);
    mpz_clears(cipherNum, modulus, NULL);
    
    return exponentStringJava;
}
        
/*This JNI function employs homomorphic properties to calculate the sum portion
 of the dot product. It calculates ciphertext1 * ciphertext2 = E(m1 + m2),
 modulo nSquared*/
JNIEXPORT jstring JNICALL Java_ServerCommunication_GMPproduct
  (JNIEnv *env, jobject obj, jstring ciphertext1, jstring ciphertext2, jstring nSquared) {
    
    // converts parameters to c strings
    const char *cipherString1 = (*env)->GetStringUTFChars(env, ciphertext1, NULL);
    if (cipherString1 == NULL) return NULL;
    const char *cipherString2 = (*env)->GetStringUTFChars(env, ciphertext2, NULL);
    if (cipherString2 == NULL) return NULL;
    const char *nSquaredString = (*env)->GetStringUTFChars(env, nSquared, NULL);
    if (nSquaredString == NULL) return NULL;
    
    // initializes gmp variables
    mpz_t cipherNum1, cipherNum2, result, modulus;
    mpz_inits(cipherNum1, cipherNum2, result, modulus, NULL);
    
    // converts c strings to gmp numbers
    int success1, success2, success3;
    success1 = mpz_set_str(cipherNum1, cipherString1, BASE);
    success2 = mpz_set_str(cipherNum2, cipherString2, BASE);
    success3 = mpz_set_str(modulus, nSquaredString, BASE);
    if (success1 == -1 || success2 == -1 || success3 == -1)
        fprintf(stderr, "Failed to convert string to number\n");
    
    // multiply two ciphertexts together, modulo n^2
    mpz_mul(result, cipherNum1, cipherNum2);
    mpz_mod(result, result, modulus);
    
    // release resources
    (*env)->ReleaseStringUTFChars(env, ciphertext1, cipherString1);
    (*env)->ReleaseStringUTFChars(env, ciphertext2, cipherString2);
    (*env)->ReleaseStringUTFChars(env, nSquared, nSquaredString);
    
    // converts result to c string
    char *productStringC = mpz_get_str(NULL, BASE, result);
    jstring productStringJava = (*env)->NewStringUTF(env, productStringC);
    
    // free memory
    free(productStringC);
    mpz_clears(cipherNum1, cipherNum2, result, modulus, NULL);
    
    // return string to java
    return productStringJava;
}

/*This helper function encrypts message, stores encrypted message in ciphertext,
 with public key g, n, nSquared. It is not used in the current application, but
 will be necessary if SkNN security is to be implemented in the future*/
void encrypt(mpz_t g, mpz_t n, mpz_t nSquared, mpz_t ciphertext, mpz_t message) {

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
		mpz_urandomm(r, r_state, n);
		mpz_gcd(gcd, r, n);
		success = mpz_cmp_ui(gcd, 1);
		// we want mpz_cmp_ui() to return 0
		if (!success)
			r_generated = 1;
	}
        
	// calculates g^m
	mpz_powm(gRaisedm, g, message, nSquared);
	
	// calculates r^n
	mpz_powm(rRaisedn, r, n, nSquared);
	
	// multiply g^m by r^n
	mpz_mul(ciphertext, gRaisedm, rRaisedn);
	
	// mod the product by n^2
	mpz_mod(ciphertext, ciphertext, nSquared);
	
	mpz_clears(gRaisedm, rRaisedn, r, gcd, NULL);
}

/* SBIT protocol part one by Jiang et.al, not used in current application */
JNIEXPORT jobjectArray JNICALL Java_ServerCommunication_SBITlooppartone
  (JNIEnv *env, jobject obj, jstring TString, jstring gString, jstring nString, jstring nSquaredString) {
    
    mpz_t Y, r, T, g, n, nSquared, encryptedR;
    mpz_inits(Y, r, T, g, n, nSquared, encryptedR, NULL);
    int success;
    
    // convert jstrings to c strings
    const char *TStringC = (*env)->GetStringUTFChars(env, TString, NULL);
    const char *gStringC = (*env)->GetStringUTFChars(env, gString, NULL);
    const char *nStringC = (*env)->GetStringUTFChars(env, nString, NULL);
    const char *nSquaredStringC = (*env)->GetStringUTFChars(env, nSquaredString, NULL);
    
    // convert c strings to mpz_t
    success = mpz_set_str(T, TStringC, BASE);
    if (success == -1) printf("Failed to convert string to number");
    success = mpz_set_str(g, gStringC, BASE);
    if (success == -1) printf("Failed to convert string to number");
    success = mpz_set_str(n, nStringC, BASE);
    if (success == -1) printf("Failed to convert string to number");
    success = mpz_set_str(nSquared, nSquaredStringC, BASE);
    if (success == -1) printf("Failed to convert string to number");
    
    // create r_state
    gmp_randstate_t r_state;
    gmp_randinit_default(r_state);
    srand(time(NULL));
    int random = rand();
    gmp_randseed_ui(r_state, random);
    
    // generates r
    mpz_urandomm(r, r_state, n);
    
    
    //encrypts r
    encrypt(g, n, nSquared, encryptedR, r);
    
    //calculates product Y = T * E(r)modN^2
    mpz_mul(Y, T, encryptedR);
    mpz_mod(Y, Y, nSquared);
    
    // stores y in c string
    char *YStringC = mpz_get_str(NULL, BASE, Y);
    char *RStringC = mpz_get_str(NULL, BASE, r);
    
    
    // converts c string to java string
    jstring YStringJava = (*env)->NewStringUTF(env, YStringC);
    jstring RStringJava = (*env)->NewStringUTF(env, RStringC);
    
    // sets two-dimensional java String array to hold Y and r
    jobjectArray ret = (*env)->NewObjectArray(env, 2,(*env)->FindClass(env,"java/lang/String"),0);
    (*env)->SetObjectArrayElement(env, ret, 0, YStringJava);
    (*env)->SetObjectArrayElement(env, ret, 1, RStringJava);
    
    // release resources
    (*env)->ReleaseStringUTFChars(env, TString, TStringC);
    (*env)->ReleaseStringUTFChars(env, gString, gStringC);
    (*env)->ReleaseStringUTFChars(env, nString, nStringC);
    (*env)->ReleaseStringUTFChars(env, nSquaredString, nSquaredStringC);
    mpz_clears(Y, r, T, g, n, nSquared, encryptedR, NULL);
    free(YStringC);
    free(RStringC);
    
    return ret;
}

/* SBIT protocol part two by Jiang et.al, not used in current application */
JNIEXPORT jobjectArray JNICALL Java_ServerCommunication_SBITloopparttwo
  (JNIEnv *env, jobject obj, jstring TString, jstring rString, 
        jstring alphaString, jstring gString, jstring nString, jstring nSquaredString) {
    
    mpz_t r, Z, T, g, n, nSquared, l, alpha, encryptedBit, one, nMinusOne;
    mpz_inits(r, Z, T, g, n, nSquared, l, alpha, encryptedBit, one, nMinusOne, NULL);
    int success;
            
    // convert jstrings to c strings
    const char *TStringC = (*env)->GetStringUTFChars(env, TString, NULL);
    const char *rStringC = (*env)->GetStringUTFChars(env, rString, NULL);
    const char *alphaStringC = (*env)->GetStringUTFChars(env, alphaString, NULL);
    const char *gStringC = (*env)->GetStringUTFChars(env, gString, NULL);
    const char *nStringC = (*env)->GetStringUTFChars(env, nString, NULL);
    const char *nSquaredStringC = (*env)->GetStringUTFChars(env, nSquaredString, NULL);
    
    // convert c strings to mpz_t
    success = mpz_set_str(T, TStringC, BASE);
    if (success == -1) printf("Failed to convert string to number");
    success = mpz_set_str(r, rStringC, BASE);
    if (success == -1) printf("Failed to convert string to number");
    success = mpz_set_str(alpha, alphaStringC, BASE);
    if (success == -1) printf("Failed to convert string to number");
    success = mpz_set_str(g, gStringC, BASE);
    if (success == -1) printf("Failed to convert string to number");
    success = mpz_set_str(n, nStringC, BASE);
    if (success == -1) printf("Failed to convert string to number");
    success = mpz_set_str(nSquared, nSquaredStringC, BASE);
    if (success == -1) printf("Failed to convert string to number");
    
    // l = 2 inverse mod n
    mpz_set_ui(l, 2);
    success = mpz_invert(l, l, n);
    if (success == 0) printf("Something went horribly wrong; n should be odd!");
    
    // r is even
    if (mpz_even_p(r))
        // set encryptedBit to alpha
        mpz_set(encryptedBit, alpha);
    // r is odd
    else {
        // set encryptedBit to E(1) * alpha^(n-1) modn^2
        mpz_sub_ui(nMinusOne, n, 1);
        mpz_set_ui(one, 1);
        // store E(1) in encryptedBit
        encrypt(g, n, nSquared, encryptedBit, one);
        // set E(xi) = E(1) * alpha^(n-1) modn^2
        // alpha is intentionally corrupted
        mpz_powm(alpha, alpha, nMinusOne, nSquared);
        mpz_mul(encryptedBit, encryptedBit, alpha);
        mpz_mod(encryptedBit, encryptedBit, nSquared);
    }
    
    // Z = T*E(xi)^(n-1) modn^2
    mpz_powm(Z, encryptedBit, nMinusOne, nSquared);
    mpz_mul(Z, Z, T);
    mpz_mod(Z, Z, nSquared);
    
    //T = Z^l modn^2
    mpz_powm(T, Z, l, nSquared);
    
    // convert E(xi) and T to c strings
    char *encryptedBitStringC = mpz_get_str(NULL, BASE, encryptedBit);
    char *updatedTStringC = mpz_get_str(NULL, BASE, T);
    
    // convert c strings to java strings
    jstring encryptedBitStringJava = (*env)->NewStringUTF(env, encryptedBitStringC);
    jstring updatedTStringJava = (*env)->NewStringUTF(env, updatedTStringC);
    
    // set two-dimensional String array to hold E(xi) and T
    jobjectArray ret = (*env)->NewObjectArray(env, 2,(*env)->FindClass(env,"java/lang/String"),0);
    (*env)->SetObjectArrayElement(env, ret, 0, encryptedBitStringJava);
    (*env)->SetObjectArrayElement(env, ret, 1, updatedTStringJava);
    
    //release resources
    (*env)->ReleaseStringUTFChars(env, TString, TStringC);
    (*env)->ReleaseStringUTFChars(env, rString, rStringC);
    (*env)->ReleaseStringUTFChars(env, alphaString, alphaStringC);
    (*env)->ReleaseStringUTFChars(env, gString, gStringC);
    (*env)->ReleaseStringUTFChars(env, nString, nStringC);
    (*env)->ReleaseStringUTFChars(env, nSquaredString, nSquaredStringC);
    mpz_clears(r, Z, T, g, n, nSquared, l, alpha, encryptedBit, one, nMinusOne, NULL);
    free(encryptedBitStringC);
    free(updatedTStringC);
    
    // return encryptedBit and T
    return ret;
}