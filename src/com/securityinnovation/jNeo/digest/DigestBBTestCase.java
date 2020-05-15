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

package com.securityinnovation.jNeo.digest;

import org.junit.Test;
import static org.junit.Assert.*;

/////////////////////////////////////////////////////////////////////////
// Tests:
//   - digest
//       - null input buffer
//       - negative input offset
//       - negative input length
//       - offset+length overrun input buffer end
//       - null output buffer
//       - negative output offset
//       - offset+output length overrun output buffer end
//       - check existing state doesn't change result
//       - check object can be reused after call
//       - known-value tests
//   - finishDigest
//       - check output is correct

public class DigestBBTestCase {

    byte randBytes[];
    byte outbuf[];

    public DigestBBTestCase()
    {
        java.util.Random r = new java.util.Random(0x4e747275);
        randBytes = new byte[256];
        r.nextBytes(randBytes);
        outbuf = new byte[20];
    }

    /////////////////////////////////////////////////////////////////////////
    // Test digest
    // 
    // Implements test case DIG-3.
    @Test(expected=NullPointerException.class)
    public void test_digest_input_null()
    {
        Sha1 s = new Sha1();
        s.digest(null, 0, 2, outbuf, 0);
    }
    
    // Implements test case DIG-7.
    @Test(expected=IllegalArgumentException.class)
    public void test_digest_input_negativeOffset()
    {
        Sha1 s = new Sha1();
        s.digest(randBytes, -1, 2, outbuf, 0);
    }
    
    // Implements test case DIG-6.
    @Test(expected=IllegalArgumentException.class)
    public void test_digest_input_negativeLength()
    {
        Sha1 s = new Sha1();
        s.digest(randBytes, 0, -1, outbuf, 0);
    }
    
    // Implements test case DIG-9.
    @Test(expected=IllegalArgumentException.class)
    public void test_digest_input_overrun()
    {
        Sha1 s = new Sha1();
        s.digest(randBytes, 2, randBytes.length, outbuf, 0);
    }
    
    // Implements test case DIG-4.
    @Test(expected=NullPointerException.class)
    public void test_digest_output_null()
    {
        Sha1 s = new Sha1();
        s.digest(randBytes, 0, 1, null, 0);
    }
    
    // Implements test case DIG-8.
    @Test(expected=IllegalArgumentException.class)
    public void test_digest_output_negativeOffset()
    {
        Sha1 s = new Sha1();
        s.digest(randBytes, 2, 1, outbuf, -1);
    }

    // Implements test case DIG-10.
    @Test(expected=IllegalArgumentException.class)
    public void test_digest_output_overrun()
    {
        Sha1 s = new Sha1();
        s.digest(randBytes, 2, 1, outbuf, outbuf.length-10);
    }
    
    // Implements test case DIG-5.
    @Test public void test_digest_inputLength_zero()
    {
        Sha1 s = new Sha1();
        s.digest(randBytes, 2, 0, outbuf, 0);
    }

    // Implements test cases DIG-1 and DIG-2.
    // digest:  check existing state doesn't change result
    // digest:  known-value tests
    @Test public void test_digest_existing_state()
    {
        Sha1 s = new Sha1();
        // update the internal state, then discard it by calling digest().
        // Save the result in outbuf.
        s.update(randBytes, 2, 1);
        s.digest(randBytes, 4, 10, outbuf, 0);
        
        // Compute the actual hash value
        s.reset();
        s.update(randBytes, 4, 10);
        assertArrayEquals(outbuf, s.finishDigest());
    }
    // digest:  check object can be reused after call
    // digest:  known-value tests
    @Test public void test_digest_resetOnReturn()
    {
        Sha1 s = new Sha1();
        s.digest(randBytes, 4, 10, outbuf, 0);
        
        // s should be reset to the initial "no input" state.
        // Finish that digest (of the empty string) and compare
        // it to what is produced by a freshly created object.
        Sha1 s2 = new Sha1();
        assertArrayEquals(s2.finishDigest(), s.finishDigest());
    }


    /////////////////////////////////////////////////////////////////////////
    // Test finishDigest(void)
    //   In these tests we assume finishDigest(byte[], int) and reset()
    //   work correctly.
    //
    // Implements test case DFD-1.
    @Test public void test_0_bytes()
    {
        Sha1 s = new Sha1();
        // Call the method we're testing
        byte b[] = s.finishDigest();
        // Call the standard finishDigest method
        s.finishDigest(outbuf, 0);
        // Check results
        assertArrayEquals(outbuf, b);
    }
    @Test public void test_14_bytes()
    {
        Sha1 s = new Sha1();
        // Call the method we're testing
        s.update(randBytes, 10, 14);
        byte b[] = s.finishDigest();
        // Call the standard finishDigest method
        s.update(randBytes, 10, 14);
        s.finishDigest(outbuf, 0);
        // Check results
        assertArrayEquals(outbuf, b);
    }
    // Implements test case DFD-2.
    @Test public void test_finishDigest_resets_object()
    {
        Sha1 s = new Sha1();

        // Call once with the empty string as the hash input
        byte b[] = s.finishDigest();

        // Call again with a non-empty input. This will only be correct
        // if the previous call reset the object.
        s.update(randBytes, 10, 14);
        b = s.finishDigest();

        // Call standard finishDigest method with same non-empty input,
        // using a new hash object.
        Sha1 s2 = new Sha1();
        s2.update(randBytes, 10, 14);
        s2.finishDigest(outbuf, 0);

        // Check results
        assertArrayEquals(outbuf, b);
    }
}
