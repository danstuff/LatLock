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

package com.securityinnovation.jNeo.math;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import org.junit.Test;
import static org.junit.Assert.*;

import com.securityinnovation.testvectors.NtruEncryptTestVector;


public class MGF_TP_1TestCase {

    // Test the byte->trit converter with 1 input byte
    @Test public void test_decode_small()
    {
        byte input[] = {48};
        ByteArrayInputStream instream = new ByteArrayInputStream(input);
        
        FullPolynomial p = MGF_TP_1.genTrinomial(5, instream);
        short output[] = {0, 1, -1, 1, 0};

        assertArrayEquals(output, p.p);
    }


    // Test the byte->trit converter ignores values >= 243.
    @Test public void test_decode_skip_invalid_input()
    {
        byte input[] = {(byte)243, (byte)244, (byte)245, (byte)255, 48};
        ByteArrayInputStream instream = new ByteArrayInputStream(input);
        
        FullPolynomial p = MGF_TP_1.genTrinomial(5, instream);
        short output[] = {0, 1, -1, 1, 0};

        assertArrayEquals(output, p.p);
    }


    // Test the byte->trit converter correctly outputs trinomials whose length
    // is not a multiple of 5.
    @Test public void test_decode_misaligned_output()
    {
        byte input[] = {(byte)243, (byte)244, (byte)245, (byte)255, 48, 4};
        ByteArrayInputStream instream = new ByteArrayInputStream(input);
        
        FullPolynomial p = MGF_TP_1.genTrinomial(7, instream);
        short output[] = {0, 1, -1, 1, 0, 1, 1};

        assertArrayEquals(output, p.p);
    }


    // Test the trit->byte converter with the decoding of 1 byte
    @Test public void test_encode_small()
    {
        short input[] = {0, 1, -1, 1, 0};
        byte expectedOutput[] = {48};

        FullPolynomial p = new FullPolynomial(input);
        ByteArrayOutputStream out = new ByteArrayOutputStream(1);
        MGF_TP_1.encodeTrinomial(p, out);
        assertArrayEquals(expectedOutput, out.toByteArray());
    }


    // Test the trit->byte converter with a long stream whose
    // length is a multiple of 5.
    @Test public void test_encode_aligned_input()
    {
        short input[] = {
            1, 1, 1, 0, -1,     0, -1, -1, -1, 0,    0, 1, 0, 0, 1,
            0, 0, -1, 0, -1,    1, 0, 1, 0, 1,       0, -1, -1, -1, 0,
            -1, 1, 1, 0, 0,     0, -1, 0, 1, 0,      0, -1, -1, 0, 0,
            1, 0, 1, -1, 1,     -1, 1, 1, 1, 0,      0,  1, 1, -1, -1,
            0, 1, 0, 0, 0};
        byte expectedOutput[] = {
            (byte) 0xaf, (byte) 0x4e, (byte) 0x54,
            (byte) 0xb4, (byte) 0x5b, (byte) 0x4e,
            (byte) 0x0e, (byte) 0x21, (byte) 0x18,
            (byte) 0x91, (byte) 0x29, (byte) 0xe4,
            (byte) 0x03};

        FullPolynomial p = new FullPolynomial(input);
        ByteArrayOutputStream out = new ByteArrayOutputStream(1);
        MGF_TP_1.encodeTrinomial(p, out);
        assertArrayEquals(expectedOutput, out.toByteArray());
    }


    // Test the trit->byte converter with a long stream whose
    // length is not a multiple of 5.
    @Test public void test_encode_misaligned_input()
    {
        short input[] = {
            1, 1, 1, 0, -1,     0, -1, -1, -1, 0,    0, 1, 0, 0, 1,
            0, 0, -1, 0, -1,    1, 0, 1, 0, 1,       0, -1, -1, -1, 0,
            -1, 1, 1, 0, 0,     0, -1, 0, 1, 0,      0, -1, -1, 0, 0,
            1, 0, 1, -1, 1,     -1, 1, 1, 1, 0,      0,  1, 1, -1, -1,
            0, 1, 0, 0, 0,      0, -1};
        byte expectedOutput[] = {
            (byte) 0xaf, (byte) 0x4e, (byte) 0x54,
            (byte) 0xb4, (byte) 0x5b, (byte) 0x4e,
            (byte) 0x0e, (byte) 0x21, (byte) 0x18,
            (byte) 0x91, (byte) 0x29, (byte) 0xe4,
            (byte) 0x03, (byte) 0x06};

        FullPolynomial p = new FullPolynomial(input);
        ByteArrayOutputStream out = new ByteArrayOutputStream(1);
        MGF_TP_1.encodeTrinomial(p, out);
        assertArrayEquals(expectedOutput, out.toByteArray());
    }


    // Verify the byte->trit and trit->byte operations really
    // are inverses for a variety of trinomials.
    @Test public void test_invertibility()
    {
        NtruEncryptTestVector tests[] = NtruEncryptTestVector.getTestVectors();
        for (int t=0; t<tests.length; t++)
        {
            FullPolynomial p = new FullPolynomial(tests[t].F);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            MGF_TP_1.encodeTrinomial(p, out);
            ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
            FullPolynomial p2 = MGF_TP_1.genTrinomial(tests[t].F.length, in);
            assertArrayEquals(p.p, p2.p);
        }
    }

}

