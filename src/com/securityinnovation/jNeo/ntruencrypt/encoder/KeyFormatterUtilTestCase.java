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

import java.util.Arrays;

import org.junit.Test;
import static org.junit.Assert.*;

import com.securityinnovation.jNeo.OID;
import com.securityinnovation.jNeo.OIDMap;
import com.securityinnovation.jNeo.NtruException;
import com.securityinnovation.jNeo.ParamSetNotSupportedException;
import com.securityinnovation.jNeo.math.FullPolynomial;
import com.securityinnovation.jNeo.ntruencrypt.KeyParams;
import com.securityinnovation.testvectors.NtruEncryptTestVector;


public class KeyFormatterUtilTestCase {

    // The master list of test vectors
    NtruEncryptTestVector tests[] = NtruEncryptTestVector.getTestVectors();

    @Test public void test_fillHeader()
        throws NtruException
    {
        byte oid[] = {2};
        byte out[] = new byte[oid.length+1];
        java.util.Arrays.fill(out, (byte)0);
        assertEquals(2, KeyFormatterUtil.fillHeader((byte) 3, oid, out));
        assertEquals(out[0], (byte)3);
        assertEquals(out[1], (byte)2);
    }

    @Test public void test_fillHeader2()
        throws NtruException
    {
        byte oid[] = {2, 9, 6};
        byte out[] = new byte[oid.length+1];
        java.util.Arrays.fill(out, (byte)0);
        assertEquals(4, KeyFormatterUtil.fillHeader((byte) 3, oid, out));
        assertEquals(out[0], (byte)3);
        assertEquals(out[1], (byte)2);
        assertEquals(out[2], (byte)9);
        assertEquals(out[3], (byte)6);
    }

    @Test public void test_fillHeader_noOutput()
        throws NtruException
    {
        byte oid[] = {2, 9, 6};
        assertEquals(4, KeyFormatterUtil.fillHeader((byte) 3, oid, null));
    }

    @Test(expected=IllegalArgumentException.class)
    public void test_short_buffer()
        throws ParamSetNotSupportedException
    {
        byte inData[] = new byte[3];
        java.util.Arrays.fill(inData, (byte)0);
        KeyFormatterUtil.parseOID(inData, 2, 3);
        fail();
    }
    
    @Test(expected=ParamSetNotSupportedException.class)
    public void test_parseOID_bad_oid()
        throws ParamSetNotSupportedException
    {
        byte inData[] = new byte[10];
        java.util.Arrays.fill(inData, (byte)0);
        KeyFormatterUtil.parseOID(inData, 1, 2);
    }


    boolean checkOID(
        OID oid)
        throws NtruException
    {
        byte inData[] = new byte[10];
        java.util.Arrays.fill(inData, (byte)0);
        byte oidBytes[] = OIDMap.getOIDBytes(oid);
        System.arraycopy(oidBytes, 0, inData, 2, oidBytes.length);
        KeyParams p = KeyFormatterUtil.parseOID(inData, 2, oidBytes.length);
        return (p == KeyParams.getKeyParams(oid));
    }

    @Test public void test_parseOID_ok()
        throws NtruException
    {
        assertTrue(checkOID(OID.ees401ep1));
        assertTrue(checkOID(OID.ees449ep1));
        assertTrue(checkOID(OID.ees677ep1));
        assertTrue(checkOID(OID.ees1087ep2));
        assertTrue(checkOID(OID.ees541ep1));
        assertTrue(checkOID(OID.ees613ep1));
        assertTrue(checkOID(OID.ees887ep1));
        assertTrue(checkOID(OID.ees1171ep1));
        assertTrue(checkOID(OID.ees659ep1));
        assertTrue(checkOID(OID.ees761ep1));
        assertTrue(checkOID(OID.ees1087ep1));
        assertTrue(checkOID(OID.ees1499ep1));
    }



    @Test public void test_recoverF()
        throws NtruException
    {
        for (int t=0; t<tests.length; t++)
        {
            KeyParams keyParams = KeyParams.getKeyParams(tests[t].oid);
            FullPolynomial f = new FullPolynomial(tests[t].f);
            // get f into the expected form:
            // The test vectors have coefficients of f in [0..q-1]
            // recoverF expects them in the range [-q/2..q/2)
            for (int i=0; i<f.p.length; i++)
            {
                if (f.p[i] > keyParams.q)
                  f.p[i] %= keyParams.q;
                if (f.p[i] > keyParams.q/2)
                  f.p[i] -= keyParams.q;
            }
            FullPolynomial F = new FullPolynomial(tests[t].F);
            FullPolynomial Fret = KeyFormatterUtil.recoverF(f);
            assertTrue(Arrays.equals(F.p, Fret.p));
        }
    }
}
