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
package com.securityinnovation.jNeo.ntruencrypt.encoder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import org.junit.Test;
import static org.junit.Assert.*;

import com.securityinnovation.jNeo.NtruException;
import com.securityinnovation.jNeo.ParamSetNotSupportedException;
import com.securityinnovation.jNeo.math.BitPack;
import com.securityinnovation.jNeo.math.FullPolynomial;
import com.securityinnovation.jNeo.math.MGF_TP_1;
import com.securityinnovation.jNeo.ntruencrypt.KeyParams;
import com.securityinnovation.testvectors.NtruEncryptTestVector;


public class PrivKeyFormatter_PrivateKeyPackedFv1TestCase {

    // The master list of test vectors
    NtruEncryptTestVector tests[] = NtruEncryptTestVector.getTestVectors();

    byte[] buildPrivBlob(
        KeyParams keyParams,
        byte      packedH[],
        byte      packedF[])
    {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        os.write(NtruEncryptKeyNativeEncoder.PRIVATE_KEY_DEFAULT_v1);
        os.write(keyParams.OIDBytes, 0, keyParams.OIDBytes.length);
        os.write(packedH, 0, packedH.length);
        os.write(packedF, 0, packedF.length);
        return os.toByteArray();
    }

    // Put f into the appropriate range [-q/2..q/2)
    FullPolynomial recoverf(
        short fBytes[],
        int   q)
    {
        FullPolynomial f = new FullPolynomial(fBytes);
        // Put f into the appropriate range [-q/2..q/2)
        for (int i=0; i<f.p.length; i++)
        {
          f.p[i] %= q;
          if (f.p[i] >= q/2)
            f.p[i] -= q;
        }
        return f;
    }
        


    @Test public void test_encodePrivKey()
        throws NtruException
    {
        for (int t=0; t<tests.length; t++)
        {
            KeyParams keyParams = KeyParams.getKeyParams(tests[t].oid);
            FullPolynomial h = new FullPolynomial(tests[t].h);
            FullPolynomial f = recoverf(tests[t].f, keyParams.q);

            // Build the test blob
            PrivKeyFormatter encoder = new PrivKeyFormatter_PrivateKeyPackedFv1();
            byte privBlob[] = encoder.encode(keyParams, h, f);

            // Build the expected blob
            byte expected[] = buildPrivBlob(
                keyParams, tests[t].packedH, tests[t].packedF);

            // Check results
            assertTrue(java.util.Arrays.equals(privBlob, expected));
        }
    }



    public void test_decodePubKey()
        throws NtruException
    {
        for (int t=0; t<tests.length; t++)
        {
            KeyParams keyParams = KeyParams.getKeyParams(tests[t].oid);

            // Build a blob
            byte blob[] = buildPrivBlob(
                keyParams, tests[t].packedH, tests[t].packedF);
            
            // Parse the test blob
            PrivKeyFormatter encoder = new PrivKeyFormatter_PrivateKeyPackedFv1();
            RawKeyData key = encoder.decode(blob);

            // Check results;
            assertEquals(key.keyParams, KeyParams.getKeyParams(tests[t].oid));
            assertTrue(java.util.Arrays.equals(key.h.p, tests[t].h));
            assertEquals(key.f, null);
        }
    }

    @Test(expected=ParamSetNotSupportedException.class)
    public void test_decodePubKey_bad_oid()
        throws NtruException
    {
        byte             blob[] = null;
        PrivKeyFormatter encoder = null;
        try {
            int t = 0;
            KeyParams keyParams = KeyParams.getKeyParams(tests[t].oid);

            // Build a blob
            blob = buildPrivBlob(
                keyParams, tests[t].packedH, tests[t].packedF);
            // Change the oid
            blob[2] = (byte)0xff;

            encoder = new PrivKeyFormatter_PrivateKeyPackedFv1();
        }
        catch (Throwable t)
        {
            fail("Unexpected exception " + t);
        }

        // Parse the test blob
        encoder.decode(blob);
    }

    @Test(expected=IllegalArgumentException.class)
    public void test_decodePubKey_shortBuf()
        throws NtruException
    {
        byte blob2[] = null;
        PrivKeyFormatter encoder = null;
        
        // Do the setup inside a try statement so we don't accidentally
        // trigger a false positive.
        try {
            int t = 0;
            KeyParams keyParams = KeyParams.getKeyParams(tests[t].oid);

            // Build a blob and make a short copy of it
            byte blob[] = buildPrivBlob(
                keyParams, tests[0].packedH, tests[0].packedListedF);
            blob2 = new byte[blob.length-2];
            System.arraycopy(blob, 0, blob2, 0, blob2.length);
        
            // Create the decoder
            encoder = new PrivKeyFormatter_PrivateKeyPackedFv1();
        }
        catch (Throwable t)
        {
            fail("setup for decoding short blob nexpectedly threw " + t.toString());
        }

        // Parse the test blob
        RawKeyData key = encoder.decode(blob2);
        fail("decoding short blob succeeded");
    }


    @Test(expected=IllegalArgumentException.class)
    public void test_decodePubKey_longBuf()
        throws NtruException
    {
        byte blob2[] = null;
        PrivKeyFormatter encoder = null;
        
        // Do the setup inside a try statement so we don't accidentally
        // trigger a false positive.
        try {
            int t = 0;
            KeyParams keyParams = KeyParams.getKeyParams(tests[t].oid);

            // Build a blob and make a long copy of it
            byte blob[] = buildPrivBlob(
                keyParams, tests[0].packedH, tests[0].packedListedF);
            blob2 = new byte[blob.length+2];
            System.arraycopy(blob, 0, blob2, 0, blob.length);
            blob2[blob.length] = blob2[blob.length+1] = 0;
        
            // Create the decoder
            encoder = new PrivKeyFormatter_PrivateKeyPackedFv1();
        }
        catch (Throwable t)
        {
            fail("setup for decoding long blob nexpectedly threw " + t.toString());
        }

        // Parse the test blob
        RawKeyData key = encoder.decode(blob2);
        fail("decoding long blob succeeded");
    }
}
