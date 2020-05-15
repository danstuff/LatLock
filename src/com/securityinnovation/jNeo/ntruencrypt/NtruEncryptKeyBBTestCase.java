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

import java.util.Arrays;
import java.io.ByteArrayInputStream;

import org.junit.Test;
import static org.junit.Assert.*;

import com.securityinnovation.jNeo.OID;
import com.securityinnovation.jNeo.Random;
import com.securityinnovation.jNeo.NtruException;
import com.securityinnovation.jNeo.CiphertextBadLengthException;
import com.securityinnovation.jNeo.PlaintextBadLengthException;
import com.securityinnovation.jNeo.DecryptionFailureException;
import com.securityinnovation.jNeo.NoPrivateKeyException;
import com.securityinnovation.jNeo.ObjectClosedException;
import com.securityinnovation.jNeo.FormatNotSupportedException;
import com.securityinnovation.jNeo.ParamSetNotSupportedException;
import com.securityinnovation.jNeo.ntruencrypt.NtruEncryptKey;
import com.securityinnovation.jNeo.inputstream.IGF2;
import com.securityinnovation.jNeo.math.FullPolynomial;
import com.securityinnovation.jNeo.math.PolynomialInverterModPrime;
import com.securityinnovation.jNeo.math.BPGM3;
import com.securityinnovation.testvectors.NtruEncryptTestVector;


/////////////////////////////////////////////////////////////////////////
// Tests:
//   - genKey
//       - null OID
//       - null PRNG
//       - positive known-value test for each OID.
//   - constructor from public/private key blob
//       - null blob
//       - bad blob tag
//       - unsupported OID
//       - corrupt blob (bad length)
//       - positive public key test for each OID
//       - positive private key test for each OID
//   - getPubKey
//       - closed object
//       - known-value test for each OID.
//   - getPrivKey
//       - closed object
//       - no private key
//       - known-value test for each OID.
//   - encrypt
//       - closed object
//       - null pt
//       - null prng
//       - pt too long
//       - known-value test for each OID.
//   - decrypt
//       - closed object
//       - null ct
//       - invalid ct len
//       - invalid ct data
//       - no private key
//       - known-value test for each OID.

public class NtruEncryptKeyBBTestCase {

    byte defaultSeed[] = new byte[32];
    Random defaultPrng = new Random(defaultSeed);

    // Get the master list of test vectors
    NtruEncryptTestVector tests[] = NtruEncryptTestVector.getTestVectors();


    /////////////////////////////////////////////////////////////////////////
    // Test genKey
    // 
    // Implements test case NGK-2.
    @Test(expected=NullPointerException.class)
    public void test_genKey_nullOID()
        throws NtruException
    {
        NtruEncryptKey.genKey(null, defaultPrng);
    }
    
    // Implements test case NGK-3.
    @Test(expected=NullPointerException.class)
    public void test_genKey_nullRandom()
        throws NtruException
    {
        NtruEncryptKey.genKey(OID.ees401ep1, (Random) null);
    }
    
    // Implements test case NGK-1.
    @Test public void test_genKey_knownInput()
        throws NtruException
    {
        for (OID oid : OID.values())
        {
            NtruEncryptTestVector test  = findTest(oid);
            Random prng = new Random(test.keygenSeed);
            NtruEncryptKey keys = NtruEncryptKey.genKey(oid, prng);
            assertArrayEquals(getPrivKeyBlob(test), keys.getPrivKey());
        }
    }


    /////////////////////////////////////////////////////////////////////////
    // Test constructor
    // 
    // Implements test case NEK-1.
    @Test(expected=NullPointerException.class)
    public void test_constructor_keyBlob_null()
        throws NtruException
    {
        new NtruEncryptKey((byte[])null);
    }
    
    // Implements test case NEK-2.
    @Test(expected=FormatNotSupportedException.class)
    public void test_constructor_bad_tag()
        throws NtruException
    {
        byte blob[] = null;
        try {
            // Get test vector
            NtruEncryptTestVector test = tests[0];
            // get public key blob
            blob = getPubKeyBlob(test);
            // change tag
            blob[0] = 41;
        }
        catch (Throwable t)
        {
            fail("Unexpected exception " + t);
        }
        // Import
        new NtruEncryptKey(blob);
    }
    
    // Implements test case NEK-3.
    @Test(expected=ParamSetNotSupportedException.class)
    public void test_constructor_bad_oid()
        throws NtruException
    {
        byte blob[] = null;
        try {
            // Get test vector
            NtruEncryptTestVector test = tests[0];
            // get public key blob
            blob = getPubKeyBlob(test);
            // change the OID
            blob[1] = 41;
        }
        catch (Throwable t)
        {
            fail("Unexpected exception " + t);
        }
        // Import
        new NtruEncryptKey(blob);
    }
    
    // Implements test case NEK-4.
    @Test(expected=IllegalArgumentException.class)
    public void test_constructor_blob_short()
        throws NtruException
    {
        byte blob[] = null;
        try {
            // Get test vector
            NtruEncryptTestVector test = tests[0];
            // get public key blob
            byte blob2[] = getPubKeyBlob(test);
            // Make a short copy
            blob = new byte[blob2.length-2];
            System.arraycopy(blob2, 0, blob, 0, blob.length);
        }
        catch (Throwable t)
        {
            fail("Unexpected exception " + t);
        }
        // Import
        new NtruEncryptKey(blob);
    }

    // Implements test case NEK-5.
    @Test(expected=IllegalArgumentException.class)
    public void test_constructor_blob_long()
        throws NtruException
    {
        byte blob[] = null;
        try {
            // Get test vector
            NtruEncryptTestVector test = tests[0];
            // get public key blob
            byte blob2[] = getPubKeyBlob(test);
            // Make a short copy
            blob = new byte[blob2.length+2];
            System.arraycopy(blob2, 0, blob, 0, blob2.length);
            blob[blob2.length] = blob[blob2.length+1] = 0;
        }
        catch (Throwable t)
        {
            fail("Unexpected exception " + t);
        }
        // Import
        new NtruEncryptKey(blob);
    }

    // constructor:  positive public key test for each OID
    //     covered by test_encrypt_known_value() below.
    // constructor:  positive private key test for each OID
    //     covered by test_decrypt_known_value() below.

    /////////////////////////////////////////////////////////////////////////
    // Test the close method
    // Implements test cases NCL-1 and NCL-2.
    @Test public void test_close()
    {
        NtruEncryptKey k = null;
        try
        {
            NtruEncryptTestVector test    = findTest(OID.ees401ep1);
            k = new NtruEncryptKey(getPubKeyBlob(test));
        }
        catch (Throwable t)
        {
            fail("Unexpected exception " + t);
        }
        k.close();
        k.close();
    }

    /////////////////////////////////////////////////////////////////////////
    // Test getPubKey
    // 
    // Implements test case GPB-2.
    @Test(expected=ObjectClosedException.class)
    public void test_getPubKey_closed()
        throws NtruException
    {
        NtruEncryptKey k = null;
        try
        {
            NtruEncryptTestVector test    = findTest(OID.ees401ep1);
            k = new NtruEncryptKey(getPubKeyBlob(test));
            k.close();
        }
        catch (Throwable t)
        {
            fail("Unexpected exception " + t);
        }
        k.getPubKey();
    }

    // Implements test case GPB-1.
    @Test public void test_getPubKey_known_value()
        throws NtruException
    {
        for (OID oid : OID.values())
        {
            NtruEncryptTestVector test  = findTest(oid);
            byte blob[]      = getPubKeyBlob(test);
            NtruEncryptKey k = new NtruEncryptKey(blob);
            byte blob2[] = k.getPubKey();
            assertArrayEquals(blob2, blob);
            if (oid == OID.ees401ep1)
              assertEquals(blob.length, 556);
            else if (oid == OID.ees449ep1)
              assertEquals(blob.length, 622);
            else if (oid == OID.ees677ep1)
              assertEquals(blob.length, 935);
            else if (oid == OID.ees1087ep2)
              assertEquals(blob.length, 1499);

            else if (oid == OID.ees541ep1)
              assertEquals(blob.length, 748);
            else if (oid == OID.ees613ep1)
              assertEquals(blob.length, 847);
            else if (oid == OID.ees887ep1)
              assertEquals(blob.length, 1224);
            else if (oid == OID.ees1171ep1)
              assertEquals(blob.length, 1615);

            else if (oid == OID.ees659ep1)
              assertEquals(blob.length, 911);
            else if (oid == OID.ees761ep1)
              assertEquals(blob.length, 1051);
            else if (oid == OID.ees1087ep1)
              assertEquals(blob.length, 1499);
            else if (oid == OID.ees1499ep1)
              assertEquals(blob.length, 2066);
        }
    }


    /////////////////////////////////////////////////////////////////////////
    // Test getPrivKey
    // 
    // Implements test case GPR-3.
    @Test(expected=ObjectClosedException.class)
    public void test_getPrivKey_closed()
        throws NtruException
    {
        NtruEncryptKey k = null;
        try
        {
            NtruEncryptTestVector test    = findTest(OID.ees401ep1);
            k = new NtruEncryptKey(getPrivKeyBlob(test));
            k.close();
        }
        catch (Throwable t)
        {
            fail("Unexpected exception " + t);
        }
        k.getPrivKey();
    }
    
    // Implements test case GPR-2.
    @Test(expected=NoPrivateKeyException.class)
    public void test_getPrivKey_noPrivKey()
        throws NtruException
    {
        NtruEncryptKey k = null;
        try
        {
            NtruEncryptTestVector test    = findTest(OID.ees401ep1);
            k = new NtruEncryptKey(getPubKeyBlob(test));
        }
        catch (Throwable t)
        {
            fail("Unexpected exception " + t);
        }
        k.getPrivKey();
    }
    
    // Implements test case GPR-1.
    @Test public void test_getPrivKey_known_value()
        throws NtruException
    {
        for (OID oid : OID.values())
        {
            NtruEncryptTestVector test  = findTest(oid);
            byte blob[]      = getPrivKeyBlob(test);
            NtruEncryptKey k = new NtruEncryptKey(blob);
            byte blob2[] = k.getPrivKey();
            assertArrayEquals(blob2, blob);
        }
    }


    /////////////////////////////////////////////////////////////////////////
    // Test encrypt
    // 
    // Implements test case NEP-4.
    @Test(expected=ObjectClosedException.class)
    public void test_encrypt_closed()
        throws NtruException
    {
        NtruEncryptKey k = null;
        try
        {
            NtruEncryptTestVector test    = findTest(OID.ees401ep1);
            k = new NtruEncryptKey(getPubKeyBlob(test));
            k.close();
        }
        catch (Throwable t)
        {
            fail("Unexpected exception " + t);
        }
        k.encrypt(defaultSeed, defaultPrng);
    }
    
    // Implements test case NEP-2.
    @Test(expected=NullPointerException.class)
    public void test_encrypt_nullPlaintext()
        throws NtruException
    {
        NtruEncryptKey k = null;
        try
        {
            NtruEncryptTestVector test    = findTest(OID.ees401ep1);
            k = new NtruEncryptKey(getPubKeyBlob(test));
        }
        catch (Throwable t)
        {
            fail("Unexpected exception " + t);
        }
        k.encrypt(null, defaultPrng);
    }
    
    // Implements test case NEP-5.
    @Test(expected=NullPointerException.class)
    public void test_encrypt_nullPrng()
        throws NtruException
    {
        NtruEncryptKey k = null;
        try
        {
            NtruEncryptTestVector test    = findTest(OID.ees401ep1);
            k = new NtruEncryptKey(getPubKeyBlob(test));
        }
        catch (Throwable t)
        {
            fail("Unexpected exception " + t);
        }
        k.encrypt(defaultSeed, (Random)null);
    }
    
    // Implements test case NEP-3.
    @Test(expected=PlaintextBadLengthException.class)
    public void test_encrypt_messageTooLong()
        throws NtruException
    {
        NtruEncryptKey k = null;
        try
        {
            NtruEncryptTestVector test    = findTest(OID.ees401ep1);
            k = new NtruEncryptKey(getPubKeyBlob(test));
        }
        catch (Throwable t)
        {
            fail("Unexpected exception " + t);
        }
        byte b[] = new byte[2*1024];
        k.encrypt(b, defaultPrng);
    }
    
    // Implements test case NEP-1.
    public void test_encrypt_known_value()
        throws NtruException
    {
        for (OID oid : OID.values())
        {
            NtruEncryptTestVector test  = findTest(oid);
            NtruEncryptKey k = new NtruEncryptKey(getPubKeyBlob(test));
            defaultPrng.seed(test.encryptSeed);
            assertArrayEquals(test.packedE, k.encrypt(test.m, defaultPrng));
        }
    }


    /////////////////////////////////////////////////////////////////////////
    // Test decrypt
    // 
    // Implements test case NDC-7.
    @Test(expected=ObjectClosedException.class)
    public void test_decrypt_closed()
        throws NtruException
    {
        NtruEncryptKey k = null;
        byte           ct[] = null;
        try
        {
            NtruEncryptTestVector test    = findTest(OID.ees401ep1);
            k = new NtruEncryptKey(getPrivKeyBlob(test));
            k.close();
            ct = test.m;
        }
        catch (Throwable t)
        {
            fail("Unexpected exception " + t);
        }
        k.decrypt(ct);
    }
    
    // Implements test case NDC-2.
    @Test(expected=NullPointerException.class)
    public void test_decrypt_nullCipherText()
        throws NtruException
    {
        NtruEncryptKey k = null;
        try
        {
            NtruEncryptTestVector test    = findTest(OID.ees401ep1);
            k = new NtruEncryptKey(getPrivKeyBlob(test));
        }
        catch (Throwable t)
        {
            fail("Unexpected exception " + t);
        }
        k.decrypt(null);
    }
    
    // Implements test case NDC-3.
    @Test(expected=CiphertextBadLengthException.class)
    public void test_decrypt_ciphertext_short()
        throws NtruException
    {
        NtruEncryptTestVector test = tests[0];
        NtruEncryptKey k = new NtruEncryptKey(getPrivKeyBlob(test));
        byte ct[] = new byte[test.packedE.length-1];
        System.arraycopy(test.packedE, 0, ct, 0, ct.length);
        k.decrypt(ct);
    }
    @Test(expected=CiphertextBadLengthException.class)
    public void test_decrypt_ciphertext_long()
        throws NtruException
    {
        NtruEncryptTestVector test = tests[0];
        NtruEncryptKey k = new NtruEncryptKey(getPrivKeyBlob(test));
        byte ct[] = new byte[test.packedE.length+1];
        System.arraycopy(test.packedE, 0, ct, 0, test.packedE.length);
        ct[ct.length-1] = 0;
        k.decrypt(ct);
    }
    
    // Implements test case NDC-5.
    @Test(expected=DecryptionFailureException.class)
    public void test_decrypt_bad_ciphertext()
        throws NtruException
    {
        NtruEncryptTestVector test = tests[0];
        NtruEncryptKey k = new NtruEncryptKey(getPrivKeyBlob(test));
        byte ct[] = new byte[test.packedE.length];
        System.arraycopy(test.packedE, 0, ct, 0, ct.length);
        ct[2]++;
        k.decrypt(ct);
    }
    
    // Implements test case NDC-6.
    @Test(expected=DecryptionFailureException.class)
    public void test_decrypt_bad_key()
        throws NtruException
    {
        NtruEncryptTestVector test = tests[0];
        // Generate a new key. The test vector key was generated with
        // test.keygenSeed, so for this new key we will seed the PRNG
        // with test.encryptSeed, which should != keygenSeed.
        Random r = new Random(test.encryptSeed);
        NtruEncryptKey k = NtruEncryptKey.genKey(test.oid, r);
        k.decrypt(test.packedE);
    }
    
    // Implements test case NDC-4.
    @Test(expected=NoPrivateKeyException.class)
    public void test_decrypt_noPrivateKey()
        throws NtruException
    {
        NtruEncryptTestVector test = tests[0];
        NtruEncryptKey k = new NtruEncryptKey(getPubKeyBlob(test));
        k.decrypt(test.packedE);
    }
    
    // Implements test case NDC-1.
    @Test public void test_decrypt_known_value()
        throws NtruException
    {
        for (OID oid : OID.values())
        {
            NtruEncryptTestVector test  = findTest(oid);
            NtruEncryptKey k = new NtruEncryptKey(getPrivKeyBlob(test));
            assertArrayEquals(test.m, k.decrypt(test.packedE));
        }
    }



    // Positive test for a parameter set: verify that
    // a key can be generated and successfully used to encrypt
    // and decrypt successfully.
    //
    // Returns true if the decrypt output matches the encrypt input,
    // false otherwise.
    // throws exception on error.
    boolean runFullTest(
        OID oid)
        throws NtruException
    {
        NtruEncryptKey keys = NtruEncryptKey.genKey(oid, defaultPrng);

        // Do encryption.
        byte m[] = new byte[10];
        byte ciphertext[] = keys.encrypt(m, defaultPrng);

        // Do decryption.
        byte m2[] = keys.decrypt(ciphertext);

        // Compare
        return Arrays.equals(m, m2);
    }

    // Run a full test for each parameter set.
    @Test public void test_positive()
        throws NtruException
    {
        for (OID oid : OID.values())
          assertTrue(runFullTest(oid));
    }


    // Find a test vector for the specified parameter set.
    NtruEncryptTestVector findTest(
        OID oid)
    {
        for (int i=0; i<tests.length; i++)
          if (oid == tests[i].oid)
            return tests[i];
        return null;
    }
    // Get a public key blob formatted with data from this test vector
    byte[] getPubKeyBlob(
        NtruEncryptTestVector tv)
    {
        byte b[] = new byte[1 + tv.oidBytes.length + tv.packedH.length];
        b[0] = 1; // tag
        System.arraycopy(tv.oidBytes, 0, b, 1, tv.oidBytes.length);
        System.arraycopy(tv.packedH, 0, b, 1+tv.oidBytes.length, tv.packedH.length);
        return b;
    }
    // Get a private key blob formatted with data from this test vector
    byte[] getPrivKeyBlob(
        NtruEncryptTestVector tv)
    {
        byte encodedF[] = null;
        if (tv.packedF.length < tv.packedListedF.length)
          encodedF = tv.packedF;
        else
          encodedF = tv.packedListedF;

        int len = 1 + tv.oidBytes.length + tv.packedH.length + encodedF.length;
        byte b[] = new byte[len];
        int off = 0;

        b[off] = 2; // tag
        off++;

        System.arraycopy(tv.oidBytes, 0, b, off, tv.oidBytes.length);
        off += tv.oidBytes.length;
        
        System.arraycopy(tv.packedH, 0, b, off, tv.packedH.length);
        off += tv.packedH.length;

        System.arraycopy(encodedF, 0, b, off, encodedF.length);
        off += encodedF.length;

        return b;
    }
}
