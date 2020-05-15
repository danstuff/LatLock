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

import org.junit.Test;
import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import com.securityinnovation.testvectors.NtruEncryptTestVector;
import com.securityinnovation.jNeo.ParamSetNotSupportedException;
import com.securityinnovation.jNeo.ntruencrypt.KeyParams;
import com.securityinnovation.jNeo.inputstream.IGF2;
import com.securityinnovation.jNeo.inputstream.MGF1;


public class BPGM3TestCase {

    // Test polynomial generation with a fixed input that will
    // produce no collisions.
    @Test public void test_oddeven()
    {
        byte igfSequence[] = {0,0,  0,2,  0,4,  0,6,  0,8,
                              0,1,  0,3,  0,5,  0,7,  0,9};
        ByteArrayInputStream is = new ByteArrayInputStream(igfSequence);
        IGF2 igf = new IGF2(0x7fff, 16, is);
        
        short polyCoeffs[] = {1, -1, 1, -1, 1, -1, 1, -1, 1, -1};
        FullPolynomial expected = new FullPolynomial(polyCoeffs);

        FullPolynomial out = BPGM3.genTrinomial(10, 5, 5, igf);

        assertTrue(out.equals(expected));
    }


    // Test polynomial generation with a fixed input that will
    // produce collisions.
    @Test public void test_collisions()
    {
        byte igfSequence[] = {0,0,  0,2,  0,4,  0,6,  
                              0,0,  0,2,  0,4,  0,6,  0,8,
                              0,0,  0,2,  0,4,  0,6,  0,8,
                              0,1,  0,3,  0,5,  0,7,  0,9};
        ByteArrayInputStream is = new ByteArrayInputStream(igfSequence);
        IGF2 igf = new IGF2(0x7fff, 16, is);
        
        short polyCoeffs[] = {1, -1, 1, -1, 1, -1, 1, -1, 1, -1};
        FullPolynomial expected = new FullPolynomial(polyCoeffs);

        FullPolynomial out = BPGM3.genTrinomial(10, 5, 5, igf);

        assertTrue(out.equals(expected));
    }


    // See if we can reproduce the generation of r for each NtruEncrypt
    // test vector
    // r = BGPM3(MGF1(dr, seed=sData));
    @Test public void test_genr()
        throws ParamSetNotSupportedException
    {
        NtruEncryptTestVector tests[] = NtruEncryptTestVector.getTestVectors();
        for (int t=0; t<tests.length; t++)
        {
            KeyParams keyParams = KeyParams.getKeyParams(tests[t].oid);
            FullPolynomial expected = new FullPolynomial(tests[t].r);
            IGF2 igf = new IGF2(
                keyParams.N, keyParams.c, keyParams.igfHash, 1,
                tests[t].sData, 0, tests[t].sData.length);
            FullPolynomial out = BPGM3.genTrinomial(
                keyParams.N, keyParams.dr, keyParams.dr, igf);

            assertTrue(out.equals(expected));
        }
    }
}

