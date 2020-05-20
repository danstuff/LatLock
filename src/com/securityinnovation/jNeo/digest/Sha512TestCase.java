/******************************************************************************
 * NTRU Cryptography Reference Source Code
 *
 * Copyright (C) 2009-2016  Security Innovation (SI)
 *
 * SI has dedicated the work to the public domain by waiving all of its rights
 * to the work worldwide under copyright law, including all related and
 * neighboring rights, to the extent allowed by law.
 *
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * You can copy, modify, distribute and perform the work, even for commercial
 * purposes, all without asking permission. You should have received a copy of
 * the creative commons license (CC0 1.0 universal) along with this program.
 * See the license file for more information. 
 *
 *
 *********************************************************************************/

 /*
  * Contents: Tests for the SHA512 class.
  *
  * This just tests the correctness of the SHA algorithm by comparing
  * its output to known test vectors. The test vectors come from the
  * cryptolib library and are a combination of the FIPS 180-2 test
  * vectors and home-grown test vectors.
  */

package com.securityinnovation.jNeo.digest;

import org.junit.Test;
import static org.junit.Assert.*;

public class Sha512TestCase {

    @Test public void test_0_bytes()
    {
        Sha512 s = new Sha512();
        assertArrayEquals(sha512_ans0, s.finishDigest());
    }
    @Test public void test_3_bytes()
    {
        Sha512 s = new Sha512();
        s.update(sha512_in, 0, 3);
        assertArrayEquals(sha512_ans3, s.finishDigest());
    }
    @Test public void test_112_bytes()
    {
        Sha512 s = new Sha512();
        s.update(sha512_in, 0, 112);
        assertArrayEquals(sha512_ans112, s.finishDigest());
    }
    @Test public void test_1000000_bytes()
    {
        Sha512 s = new Sha512();
        for (int i=0; i<1000; i++)
          s.update(sha512_in_a, 0, sha512_in_a.length);
        assertArrayEquals(sha512_ans1000000, s.finishDigest());
    }


    static final byte sha512_in[] = {
        (byte)0x61, (byte)0x62, (byte)0x63, (byte)0x64,
        (byte)0x65, (byte)0x66, (byte)0x67, (byte)0x68,
        (byte)0x62, (byte)0x63, (byte)0x64, (byte)0x65,
        (byte)0x66, (byte)0x67, (byte)0x68, (byte)0x69,
        (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66,
        (byte)0x67, (byte)0x68, (byte)0x69, (byte)0x6a,
        (byte)0x64, (byte)0x65, (byte)0x66, (byte)0x67,
        (byte)0x68, (byte)0x69, (byte)0x6a, (byte)0x6b,
        (byte)0x65, (byte)0x66, (byte)0x67, (byte)0x68,
        (byte)0x69, (byte)0x6a, (byte)0x6b, (byte)0x6c,
        (byte)0x66, (byte)0x67, (byte)0x68, (byte)0x69,
        (byte)0x6a, (byte)0x6b, (byte)0x6c, (byte)0x6d,
        (byte)0x67, (byte)0x68, (byte)0x69, (byte)0x6a,
        (byte)0x6b, (byte)0x6c, (byte)0x6d, (byte)0x6e,
        (byte)0x68, (byte)0x69, (byte)0x6a, (byte)0x6b,
        (byte)0x6c, (byte)0x6d, (byte)0x6e, (byte)0x6f,
        (byte)0x69, (byte)0x6a, (byte)0x6b, (byte)0x6c,
        (byte)0x6d, (byte)0x6e, (byte)0x6f, (byte)0x70,
        (byte)0x6a, (byte)0x6b, (byte)0x6c, (byte)0x6d,
        (byte)0x6e, (byte)0x6f, (byte)0x70, (byte)0x71,
        (byte)0x6b, (byte)0x6c, (byte)0x6d, (byte)0x6e,
        (byte)0x6f, (byte)0x70, (byte)0x71, (byte)0x72,
        (byte)0x6c, (byte)0x6d, (byte)0x6e, (byte)0x6f,
        (byte)0x70, (byte)0x71, (byte)0x72, (byte)0x73,
        (byte)0x6d, (byte)0x6e, (byte)0x6f, (byte)0x70,
        (byte)0x71, (byte)0x72, (byte)0x73, (byte)0x74,
        (byte)0x6e, (byte)0x6f, (byte)0x70, (byte)0x71,
        (byte)0x72, (byte)0x73, (byte)0x74, (byte)0x75,
    };
    
    static final byte sha512_ans0[] = {
        (byte)0xcf, (byte)0x83, (byte)0xe1, (byte)0x35,
        (byte)0x7e, (byte)0xef, (byte)0xb8, (byte)0xbd,
        (byte)0xf1, (byte)0x54, (byte)0x28, (byte)0x50,
        (byte)0xd6, (byte)0x6d, (byte)0x80, (byte)0x07,
        (byte)0xd6, (byte)0x20, (byte)0xe4, (byte)0x05,
        (byte)0x0b, (byte)0x57, (byte)0x15, (byte)0xdc,
        (byte)0x83, (byte)0xf4, (byte)0xa9, (byte)0x21,
        (byte)0xd3, (byte)0x6c, (byte)0xe9, (byte)0xce,
        (byte)0x47, (byte)0xd0, (byte)0xd1, (byte)0x3c,
        (byte)0x5d, (byte)0x85, (byte)0xf2, (byte)0xb0,
        (byte)0xff, (byte)0x83, (byte)0x18, (byte)0xd2,
        (byte)0x87, (byte)0x7e, (byte)0xec, (byte)0x2f,
        (byte)0x63, (byte)0xb9, (byte)0x31, (byte)0xbd,
        (byte)0x47, (byte)0x41, (byte)0x7a, (byte)0x81,
        (byte)0xa5, (byte)0x38, (byte)0x32, (byte)0x7a,
        (byte)0xf9, (byte)0x27, (byte)0xda, (byte)0x3e,
    };

    static final byte sha512_ans3[] = {
        (byte)0xdd, (byte)0xaf, (byte)0x35, (byte)0xa1,
        (byte)0x93, (byte)0x61, (byte)0x7a, (byte)0xba,
        (byte)0xcc, (byte)0x41, (byte)0x73, (byte)0x49,
        (byte)0xae, (byte)0x20, (byte)0x41, (byte)0x31,
        (byte)0x12, (byte)0xe6, (byte)0xfa, (byte)0x4e,
        (byte)0x89, (byte)0xa9, (byte)0x7e, (byte)0xa2,
        (byte)0x0a, (byte)0x9e, (byte)0xee, (byte)0xe6,
        (byte)0x4b, (byte)0x55, (byte)0xd3, (byte)0x9a,
        (byte)0x21, (byte)0x92, (byte)0x99, (byte)0x2a,
        (byte)0x27, (byte)0x4f, (byte)0xc1, (byte)0xa8,
        (byte)0x36, (byte)0xba, (byte)0x3c, (byte)0x23,
        (byte)0xa3, (byte)0xfe, (byte)0xeb, (byte)0xbd,
        (byte)0x45, (byte)0x4d, (byte)0x44, (byte)0x23,
        (byte)0x64, (byte)0x3c, (byte)0xe8, (byte)0x0e,
        (byte)0x2a, (byte)0x9a, (byte)0xc9, (byte)0x4f,
        (byte)0xa5, (byte)0x4c, (byte)0xa4, (byte)0x9f,
    };

    static final byte sha512_ans112[] = {
        (byte)0x8e, (byte)0x95, (byte)0x9b, (byte)0x75,
        (byte)0xda, (byte)0xe3, (byte)0x13, (byte)0xda,
        (byte)0x8c, (byte)0xf4, (byte)0xf7, (byte)0x28,
        (byte)0x14, (byte)0xfc, (byte)0x14, (byte)0x3f,
        (byte)0x8f, (byte)0x77, (byte)0x79, (byte)0xc6,
        (byte)0xeb, (byte)0x9f, (byte)0x7f, (byte)0xa1,
        (byte)0x72, (byte)0x99, (byte)0xae, (byte)0xad,
        (byte)0xb6, (byte)0x88, (byte)0x90, (byte)0x18,
        (byte)0x50, (byte)0x1d, (byte)0x28, (byte)0x9e,
        (byte)0x49, (byte)0x00, (byte)0xf7, (byte)0xe4,
        (byte)0x33, (byte)0x1b, (byte)0x99, (byte)0xde,
        (byte)0xc4, (byte)0xb5, (byte)0x43, (byte)0x3a,
        (byte)0xc7, (byte)0xd3, (byte)0x29, (byte)0xee,
        (byte)0xb6, (byte)0xdd, (byte)0x26, (byte)0x54,
        (byte)0x5e, (byte)0x96, (byte)0xe5, (byte)0x5b,
        (byte)0x87, (byte)0x4b, (byte)0xe9, (byte)0x09,
    };

    static final byte sha512_in_a[] = {
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
    };

    static final byte sha512_ans1000000[] = {
        (byte)0xe7, (byte)0x18, (byte)0x48, (byte)0x3d,
        (byte)0x0c, (byte)0xe7, (byte)0x69, (byte)0x64,
        (byte)0x4e, (byte)0x2e, (byte)0x42, (byte)0xc7,
        (byte)0xbc, (byte)0x15, (byte)0xb4, (byte)0x63,
        (byte)0x8e, (byte)0x1f, (byte)0x98, (byte)0xb1,
        (byte)0x3b, (byte)0x20, (byte)0x44, (byte)0x28,
        (byte)0x56, (byte)0x32, (byte)0xa8, (byte)0x03,
        (byte)0xaf, (byte)0xa9, (byte)0x73, (byte)0xeb,
        (byte)0xde, (byte)0x0f, (byte)0xf2, (byte)0x44,
        (byte)0x87, (byte)0x7e, (byte)0xa6, (byte)0x0a,
        (byte)0x4c, (byte)0xb0, (byte)0x43, (byte)0x2c,
        (byte)0xe5, (byte)0x77, (byte)0xc3, (byte)0x1b,
        (byte)0xeb, (byte)0x00, (byte)0x9c, (byte)0x5c,
        (byte)0x2c, (byte)0x49, (byte)0xaa, (byte)0x2e,
        (byte)0x4e, (byte)0xad, (byte)0xb2, (byte)0x17,
        (byte)0xad, (byte)0x8c, (byte)0xc0, (byte)0x9b,
    };
}