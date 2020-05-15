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
package com.securityinnovation.jNeo.ntruencrypt;

import java.io.ByteArrayInputStream;

import org.junit.Test;
import static org.junit.Assert.*;

import com.securityinnovation.jNeo.OID;
import com.securityinnovation.jNeo.NtruException;
import com.securityinnovation.jNeo.ntruencrypt.NtruEncryptKey;
import com.securityinnovation.jNeo.inputstream.IGF2;
import com.securityinnovation.jNeo.math.BitPack;
import com.securityinnovation.jNeo.math.FullPolynomial;
import com.securityinnovation.jNeo.math.PolynomialInverterModPrime;
import com.securityinnovation.jNeo.math.BPGM3;
import com.securityinnovation.testvectors.NtruEncryptTestVector;

public class NtruEncryptKeyTestCase {

    // Get the master list of test vectors
    NtruEncryptTestVector tests[] = NtruEncryptTestVector.getTestVectors();

    // Make sure M = <b || l || m || p0> is generated properly
    // for each parameter set. We do this by just running through the
    // test vectors.
    @Test public void test_generateM()
        throws NtruException
    {
        for (int t=0; t<tests.length; t++)
        {
            ByteArrayInputStream rng = new ByteArrayInputStream(tests[t].b);
            NtruEncryptKey keys = new NtruEncryptKey(tests[t].oid);
            byte M[] = keys.generateM(tests[t].m, rng);
            assertArrayEquals(tests[t].Mbin, M);
        }
    }


    // Make sure sData = <OID || m || b || hTrun> is generated properly
    // for each parameter set. We do this by running through all of
    // the test vectors.
    // This only considers the case where m and b are their own
    // vectors (specifically, mOffset and bOffset are 0).
    @Test public void test_form_sData()
        throws NtruException
    {
        for (int t=0; t<tests.length; t++)
        {
            KeyParams keyParams = KeyParams.getKeyParams(tests[t].oid);
            NtruEncryptKey keys = new NtruEncryptKey(tests[t].oid);
            keys.h = new FullPolynomial(tests[t].h);
            byte sData[] = keys.form_sData(
                tests[t].m, 0, tests[t].m.length, tests[t].b, 0);
            assertArrayEquals(tests[t].sData, sData);
        }
    }

    // Same as test_form_sData(), but make mOffset and bOffset non-zero.
    @Test public void test_form_sData_embedded()
        throws NtruException
    {
        for (int t=0; t<tests.length; t++)
        {
            KeyParams keyParams = KeyParams.getKeyParams(tests[t].oid);
            NtruEncryptKey keys = new NtruEncryptKey(tests[t].oid);
            keys.h = new FullPolynomial(tests[t].h);

            byte data[] = new byte[tests[t].m.length + tests[t].b.length + 92];
            java.util.Arrays.fill(data, (byte) 23);
            int mOffset = 33;
            int bOffset = 72;
            System.arraycopy(tests[t].m, 0, data, mOffset, tests[t].m.length);
            System.arraycopy(tests[t].b, 0, data, bOffset, tests[t].b.length);
            byte sData[] = keys.form_sData(
                data, mOffset, tests[t].m.length, data, bOffset);
            assertArrayEquals(tests[t].sData, sData);
        }
    }


    // Test that the primitive that converts 3 bits to 2 trits works correctly.
    @Test public void test_convPolyBinaryToTrinaryHelper()
        throws NtruException
    {
        NtruEncryptKey keys = new NtruEncryptKey(OID.ees401ep1);

        short out[] = new short[16];
        java.util.Arrays.fill(out, (short) 22);   // init to invalid data

        // Check each bit pattern in [0..8).
        keys.convPolyBinaryToTrinaryHelper(out.length, 0, out, 7);
        keys.convPolyBinaryToTrinaryHelper(out.length, 2, out, 6);
        keys.convPolyBinaryToTrinaryHelper(out.length, 4, out, 5);
        keys.convPolyBinaryToTrinaryHelper(out.length, 6, out, 4);
        keys.convPolyBinaryToTrinaryHelper(out.length, 8, out, 3);
        keys.convPolyBinaryToTrinaryHelper(out.length, 10, out, 2);
        keys.convPolyBinaryToTrinaryHelper(out.length, 12, out, 1);
        keys.convPolyBinaryToTrinaryHelper(out.length, 14, out, 0);

        // Manually computed expected output
        short expectedOut[] = {
            -1, 1,   -1, 0,    1, -1,    1, 1,    1, 0,   0, -1,   0, 1,   0, 0
        };
        assertArrayEquals(out, expectedOut);
    }

    // Test that the primitive that converts a block of bits to a block
    // of trits works correctly (1 block == 16 trits == 24 bits (3 bytes)).
    @Test public void test_convPolyBinaryToTrinaryHelper2_a()
        throws NtruException
    {
        NtruEncryptKey keys = new NtruEncryptKey(OID.ees401ep1);

        short out[] = new short[19];
        java.util.Arrays.fill(out, (short) 22);   // init to invalid data

        keys.convPolyBinaryToTrinaryHelper2(out.length, 3, out, 0x00e1e83a);
        short expectedOut[] = {
            22, 22, 22,
            -1, 1, 0, 0, 1, 0, -1, 0, 1, 1, 0, 0, -1, 1, 0, -1
        };

        assertArrayEquals(out, expectedOut);
    }

    // Test that the primitive that converts a block of bits to a block
    // of trits works correctly (1 block == 16 trits == 24 bits (3 bytes)).
    // with a different sample input than the _a() version.
    @Test public void test_convPolyBinaryToTrinaryHelper2_b()
        throws NtruException
    {
        NtruEncryptKey keys = new NtruEncryptKey(OID.ees401ep1);
        short out[] = new short[16];
        java.util.Arrays.fill(out, (short) 22);   // init to invalid data
        keys.convPolyBinaryToTrinaryHelper2(out.length, 0, out, 0x00c8a669);

        short expectedOut[] = {
            -1, 0, 0, -1, 0, 1, 0, -1, 1, 0, 0, 1, 1, -1, 0, 1
        };
        assertArrayEquals(out, expectedOut);
    }


    // Test that the full conversion from binary polynomial to trinary
    // polynomial works correctly.
    // To get a variety of sample inputs we use the test vectors.
    @Test public void test_convPolyBinaryToTrinary()
        throws NtruException
    {
        for (int t=0; t<tests.length; t++)
        {
            KeyParams keyParams = KeyParams.getKeyParams(tests[t].oid);
            NtruEncryptKey keys = new NtruEncryptKey(tests[t].oid);
            short out[] = keys.convPolyBinaryToTrinary(
                keyParams.N, tests[t].Mbin);
            assertArrayEquals(out, tests[t].Mtrin);
        }
    }

                           
    // Test that the primitive that converts 2 trits to 3 bits works correctly.
    @Test public void test_convPolyTritToBitHelper()
        throws NtruException
    {
        // the particular OID doesn't matter here, we just need an object
        NtruEncryptKey keys = new NtruEncryptKey(OID.ees401ep1);

        assertEquals((byte) 0, keys.convPolyTritToBitHelper( 0,  0));
        assertEquals((byte) 1, keys.convPolyTritToBitHelper( 0,  1));
        assertEquals((byte) 2, keys.convPolyTritToBitHelper( 0, -1));
        assertEquals((byte) 3, keys.convPolyTritToBitHelper( 1,  0));
        assertEquals((byte) 4, keys.convPolyTritToBitHelper( 1,  1));
        assertEquals((byte) 5, keys.convPolyTritToBitHelper( 1, -1));
        assertEquals((byte) 6, keys.convPolyTritToBitHelper(-1,  0));
        assertEquals((byte) 7, keys.convPolyTritToBitHelper(-1,  1));
        assertEquals((byte) -1, keys.convPolyTritToBitHelper(-1, -1));

        // Other invalid values
        assertEquals((byte) -1, keys.convPolyTritToBitHelper(0, 3));
    }


    // Test that the primitive that converts a block of trits to a block
    // of bits works correctly (1 block == 16 trits == 24 bits (3 bytes)).
    @Test public void test_convPolyTritToBitBlockHelper()
        throws NtruException
    {
        // the particular OID doesn't matter here, we just need an object
        NtruEncryptKey keys = new NtruEncryptKey(OID.ees401ep1);

        short trits[] = {
            1, -1,  0,  0, -1,  1,  1,  1,
            0,  0,  1,  0,  0,  1,  1,  1};
        byte expectedBits[] = {(byte)0xa3, (byte)0xc0, (byte)0xcc};
        byte bits[] = new byte[3];

        keys.convPolyTrinaryToBinaryBlockHelper(0, trits, 0, bits);
        assertArrayEquals(bits, expectedBits);
    }

    // Test that the primitive that converts a block of trits to a block
    // of bits works with non-zero offsets for both the bit and trit arrays.
    @Test public void test_convPolyTritToBitBlockHelper_withOffset()
        throws NtruException
    {
        // the particular OID doesn't matter here, we just need an object
        NtruEncryptKey keys = new NtruEncryptKey(OID.ees401ep1);

        short trits[] = {
            0,  0,  0,  0,  0,  0,  0,  0,
            0,  0,  0,  0,  0,  0,  0,  0,
            1, -1,  0,  0, -1,  1,  1,  1,
            0,  0,  1,  0,  0,  1,  1,  1};
        byte expectedBits[] = {22, 22, 22, (byte)0xa3, (byte)0xc0, (byte)0xcc};
        byte bits[] = new byte[6];
        java.util.Arrays.fill(bits, (byte)22);

        keys.convPolyTrinaryToBinaryBlockHelper(16, trits, 3, bits);
        assertArrayEquals(bits, expectedBits);
    }

    // Test that the primitive that converts a block of trits to a block
    // of bits won't overrun the end of the output buffer.
    @Test public void test_convPolyTritToBitBlockHelper_withOffset_truncate()
        throws NtruException
    {
        // the particular OID doesn't matter here, we just need an object
        NtruEncryptKey keys = new NtruEncryptKey(OID.ees401ep1);

        short trits[] = {
            0,  0,  0,  0,  0,  0,  0,  0,
            0,  0,  0,  0,  0,  0,  0,  0,
            1, -1,  0,  0, -1,  1,  1,  1,
            0,  0,  1,  0,  0,  1,  1,  1};
        byte expectedBits[] = {22, 22, 22, (byte)0xa3, (byte)0xc0};
        byte bits[] = new byte[5];
        java.util.Arrays.fill(bits, (byte)22);

        keys.convPolyTrinaryToBinaryBlockHelper(16, trits, 3, bits);
        assertArrayEquals(bits, expectedBits);
    }

    // Test that the primitive that converts a block of trits to a block
    // of bits won't overrun the end of the input buffer. It should
    // behave as if the input were padded with 0's.
    @Test public void test_convPolyTritToBitBlockHelper_withOffset_short_inbuf()
        throws NtruException
    {
        // the particular OID doesn't matter here, we just need an object
        NtruEncryptKey keys = new NtruEncryptKey(OID.ees401ep1);

        short trits[] = {
            0,  0,  0,  0,  0,  0,  0,  0,
            0,  0,  0,  0,  0,  0,  0,  0,
            0,  0,  1,  0,  0,  1,  1,  1,
            1, -1,  0,  0, -1}; // missing last 11 trits,
        byte expectedBits[] = {22, 22, 22, (byte)0xa3, (byte)0x00, (byte)0x00};
        byte bits[] = new byte[6];
        java.util.Arrays.fill(bits, (byte)22);

        keys.convPolyTrinaryToBinaryBlockHelper(24, trits, 3, bits);
        assertArrayEquals(bits, expectedBits);
    }


    // Test that the full conversion from trinary polynomial to binary
    // polynomial works correctly.
    // To get a variety of sample inputs we use the test vectors.
    @Test public void test_convPolyTrinaryToBinary()
        throws NtruException
    {
        for (int t=0; t<tests.length; t++)
        {
            KeyParams keyParams = KeyParams.getKeyParams(tests[t].oid);
            NtruEncryptKey keys = new NtruEncryptKey(tests[t].oid);
            
            FullPolynomial Mtrin = new FullPolynomial(tests[t].Mtrin);
            byte out[] = keys.convPolyTrinaryToBinary(Mtrin);
            assertArrayEquals(out, tests[t].Mbin);
        }
    }


    // Verify that the calculation (P mod 4) works correctly for a variety
    // of polynomials P.
    @Test public void test_calcPolyMod4Packed()
        throws NtruException
    {
        for (int t=0; t<tests.length; t++)
        {
            KeyParams keyParams = KeyParams.getKeyParams(tests[t].oid);
            NtruEncryptKey keys = new NtruEncryptKey(tests[t].oid);
            FullPolynomial R = new FullPolynomial(tests[t].R);
            byte out[] = keys.calcPolyMod4Packed(R);
            assertArrayEquals(out, tests[t].R4);
        }
    }


    // Verify that the calculation of the encryption mask polynomial
    // from r*h is correct. Use the test vectors as sample input
    @Test public void test_calcEncryptionMask()
        throws NtruException
    {
        for (int t=0; t<tests.length; t++)
        {
            KeyParams keyParams = KeyParams.getKeyParams(tests[t].oid);
            NtruEncryptKey keys = new NtruEncryptKey(tests[t].oid);
            FullPolynomial out = 
              keys.calcEncryptionMask(new FullPolynomial(tests[t].R));
            assertArrayEquals(out.p, tests[t].mask);
        }
    }


    // Verify that the the dm0 check is correct for all 3 failure cases.
    // and for the positive case
    @Test public void test_check_dm0()
        throws NtruException
    {
        NtruEncryptKey keys = new NtruEncryptKey(OID.ees401ep1);

        // Check the ability to count 1's.
        // Verify the boundary case and one case on each side of the dm0 limit
        short threeOnesArray[] = {-1, -1, -1, -1, -1, 0, 0, 0, 0, 0, 1, 1, 1};
        FullPolynomial threeOnes = new FullPolynomial(threeOnesArray);
        assertFalse(keys.check_dm0(threeOnes, 4));
        assertTrue(keys.check_dm0(threeOnes, 3));
        assertTrue(keys.check_dm0(threeOnes, 2));

        // Check the ability to count 0's.
        // Verify the boundary case and one case on each side of the dm0 limit
        short threeZerosArray[] = {-1, -1, -1, -1, -1, 0, 0, 0, 1, 1, 1, 1, 1};
        FullPolynomial threeZeros = new FullPolynomial(threeZerosArray);
        assertFalse(keys.check_dm0(threeZeros, 4));
        assertTrue(keys.check_dm0(threeZeros, 3));
        assertTrue(keys.check_dm0(threeZeros, 2));

        // Check the ability to count -1's.
        // Verify the boundary case and one case on each side of the dm0 limit
        short threeNegOnesArray[] = {-1, -1, -1, -1, -1,  0,0,0,0,0,  1,1,1};
        FullPolynomial threeNegOnes = new FullPolynomial(threeNegOnesArray);
        assertFalse(keys.check_dm0(threeNegOnes, 4));
        assertTrue(keys.check_dm0(threeNegOnes, 3));
        assertTrue(keys.check_dm0(threeNegOnes, 2));
    }



    // Verify parseMgsLengthFromM won't crash if given a short input buffer
    @Test public void test_parseMgsLengthFromM_short_buffer()
        throws NtruException
    {
        for (int t=0; t<tests.length; t++)
        {
            KeyParams keyParams = KeyParams.getKeyParams(tests[t].oid);
            NtruEncryptKey keys = new NtruEncryptKey(tests[t].oid);

            byte M[] = new byte[keyParams.db/8-1];
            java.util.Arrays.fill(M, (byte) 0);            
            assertEquals(0, keys.parseMsgLengthFromM(M));
        }
    }

    // Verify parseMsgLengthFromM pulls out the correct bits for
    // a variety of message lengths for each parameter set.
    @Test public void test_parseMgsLengthFromM()
        throws NtruException
    {
        for (int t=0; t<tests.length; t++)
        {
            KeyParams keyParams = KeyParams.getKeyParams(tests[t].oid);
            NtruEncryptKey keys = new NtruEncryptKey(tests[t].oid);

            byte M[] = new byte[keyParams.N];
            java.util.Arrays.fill(M, (byte) 0);
            for (int i=1; i<12; i++)
            {
                M[keyParams.db/8] = (byte) i;
                assertEquals(i, keys.parseMsgLengthFromM(M));
            }
        }
    }

    // Verify verifyMFormat generates an appropriate error when given
    // a short input buffer.
    @Test public void test_verifyMFormat_shortInputBuffer()
        throws NtruException
    {
        KeyParams keyParams = KeyParams.getKeyParams(OID.ees401ep1);
        NtruEncryptKey keys = new NtruEncryptKey(OID.ees401ep1);

        byte M[] = new byte[keyParams.N-2];
        java.util.Arrays.fill(M, (byte) 0);
        M[keyParams.db/8] = 1;
        assertEquals(-1, keys.verifyMFormat(M));
    }

    // Verify verifyMFormat generates an appropriate error when the
    // embedded mLen is invalid.
    @Test public void test_verifyMFormat_invalidMLen()
        throws NtruException
    {
        KeyParams keyParams = KeyParams.getKeyParams(OID.ees401ep1);
        NtruEncryptKey keys = new NtruEncryptKey(OID.ees401ep1);

        byte M[] = new byte[keyParams.N];
        java.util.Arrays.fill(M, (byte) 0);
        M[keyParams.db/8] = (byte) 401;
        assertEquals(-1, keys.verifyMFormat(M));
    }

    // Verify verifyMFormat generates an appropriate error when p0 is incorrect
    @Test public void test_verifyMFormat_invalidp0()
        throws NtruException
    {
        KeyParams keyParams = KeyParams.getKeyParams(OID.ees401ep1);
        NtruEncryptKey keys = new NtruEncryptKey(OID.ees401ep1);

        byte M[] = new byte[keyParams.N];
        java.util.Arrays.fill(M, (byte) 0);
        M[keyParams.db/8] = 1;
        M[keyParams.db/8+keyParams.lLen+1+1] = 2;
        assertEquals(-1, keys.verifyMFormat(M));
    }

    // Verify the positive case of test_verifyMFormat()
    @Test public void test_verifyMFormat()
        throws NtruException
    {
        for (int t=0; t<tests.length; t++)
        {
            KeyParams keyParams = KeyParams.getKeyParams(tests[t].oid);
            NtruEncryptKey keys = new NtruEncryptKey(tests[t].oid);

            byte M[] = new byte[keyParams.db/8 + keyParams.lLen +
                                keyParams.maxMsgLenBytes + 1];
            java.util.Arrays.fill(M, (byte) 0);
            M[keyParams.db/8] = (byte) 1;
            java.util.Arrays.fill(M, keyParams.db/8+keyParams.lLen,
                                  keyParams.db/8+keyParams.lLen+1, (byte) 22);
            assertEquals(1, keys.verifyMFormat(M));
        }
    }

    // A full passthrough for each test vector:
    // verify encrypt() produces the correct output
    // verify decrypt() produces the correct output
    @Test public void test_encdec()
        throws NtruException
    {
        for (int t=0; t<tests.length; t++)
        {
            KeyParams keyParams = KeyParams.getKeyParams(tests[t].oid);
            NtruEncryptKey keys = new NtruEncryptKey(tests[t].oid);

            // Set f, h.
            keys.h = new FullPolynomial(tests[t].h);
            keys.f = new FullPolynomial(tests[t].f);

            // Do encryption
            ByteArrayInputStream prng = new ByteArrayInputStream(tests[t].b);
            byte ciphertext[] = keys.encrypt(tests[t].m, prng);

            byte m[] = keys.decrypt(ciphertext);
            assertArrayEquals(tests[t].m, m);
        }
    }
}
