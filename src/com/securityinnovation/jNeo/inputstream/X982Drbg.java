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

package com.securityinnovation.jNeo.inputstream;

import java.io.InputStream;
import com.securityinnovation.jNeo.digest.DigestAlgorithm;
import static com.securityinnovation.jNeo.digest.DigestAlgorithm.*;
import com.securityinnovation.jNeo.digest.Digest;

/**
 * This class implements an InputStream whose output conforms to
 * the X9.82 specification for "Hash Function DRBG Using Any Approved
 * Hash Function" (section 10.1.3 of ANS X9.82, Part 3, Draft July 2003).
 *
 * <p>In addition to the InputStream API, this class also adds
 * functions for seeding and reseeding the DRBG.
 */
public class X982Drbg extends InputStream
{
    /**
     * Constructor that takes a seed to start the RNG
     */
    public X982Drbg(
        DigestAlgorithm hashAlgorithm,
        byte[]           _seed)
    {
        mHash = hashAlgorithm.newInstance();
        seed(_seed);
    }

    // This value of t comes from Annex E of X9.82-3, in the section
    // on digital signtures. The recommended value of t for each
    // hash algorithm is the leading <n> bytes of this string,
    // where n = the digest length of the hash algorithm.
    private final static byte t[] = {
        (byte)0xcf, (byte)0x83, (byte)0xe1, (byte)0x35, (byte)0x7e,
        (byte)0xef, (byte)0xb8, (byte)0xbd, (byte)0xf1, (byte)0x54,
        (byte)0x28, (byte)0x50, (byte)0xd6, (byte)0x6d, (byte)0x80,
        (byte)0x07, (byte)0xd6, (byte)0x20, (byte)0xe4, (byte)0x05,
        (byte)0x0b, (byte)0x57, (byte)0x15, (byte)0xdc, (byte)0x83,
        (byte)0xf4, (byte)0xa9, (byte)0x21, (byte)0xd3, (byte)0x6c,
        (byte)0xe9, (byte)0xce, (byte)0x47, (byte)0xd0, (byte)0xd1,
        (byte)0x3c, (byte)0x5d, (byte)0x85, (byte)0xf2, (byte)0xb0,
        (byte)0xff, (byte)0x83, (byte)0x18, (byte)0xd2, (byte)0x87,
        (byte)0x7e, (byte)0xec, (byte)0x2f, (byte)0x63, (byte)0xb9,
        (byte)0x31, (byte)0xbd, (byte)0x47, (byte)0x41, (byte)0x7a,
        (byte)0x81, (byte)0xa5, (byte)0x38, (byte)0x32, (byte)0x7a,
        (byte)0xf9, (byte)0x27, (byte)0xda, (byte)0x3e
    };


    /**
     * Implement the Initialize_Hash_DRBG algorithm from the X9.82 spec.
     * This implementation does not support an application purpose
     * (the variable t). It also does not enforce the minimum entropy
     * requirements, or checks on the desired strength..
     */
    public void seed(
        byte[] _seed)
    {
        // TBD: Sanity-check seed based on hash alg?
        // sha1   --> len>160/8
        // sha256 --> len>256/8
        // sha512 --> len>512/8

        ctr = 1;

        // Set V = _seed
        V = new byte[_seed.length];
        System.arraycopy(_seed, 0, V, 0, _seed.length);

        // Preallocate a temp buffer large enough to hold V, and
        // large enough to hold a digest.
        int hashLen = mHash.getDigestLen();
        int VtmpLen = Math.max(V.length, hashLen);
        if ((Vtmp == null) || (Vtmp.length != VtmpLen))
          Vtmp = new byte[VtmpLen];

        // Calculate C = Hash(t || V) mod 2^B
        C = new byte[hashLen];
        mHash.update(t, 0, hashLen);
        mHash.update(V, 0, V.length);
        mHash.finishDigest(C, 0);
    }


    /**
     * Implement the Reseed_Hash_DRBG algorithm from the X9.82 spec.
     * This implementation does not support an application purpose
     * (the variable t). It also does not enforce the minimum entropy
     * requirements.
     */
    public void reseed(
        byte[] _seed)
    {
        // Reset ctr to 1.
        ctr = 1;

        // Set new V = leftmost _seed.length bits of
        //                Hash(V | newSeed | 0x01) |
        //                Hash(V | newSeed | 0x02) |
        //                Hash(V | newSeed | 0x03) |
        //                ...
        // 
        // so that new V.length = _seed.length.

        // tmp = V | newSeed | 0x01
        byte tmp[] = new byte[V.length + _seed.length + 1];
        System.arraycopy(V, 0, tmp, 0, V.length);
        System.arraycopy(_seed, 0, tmp, V.length, _seed.length);
        tmp[tmp.length-1] = 1;

        // Allocate a buffer to hold the new V. 
        // Do as many full blocks as we can directly into newV
        // then do a final update into tmp and extract a partial block.
        int    hashLen = mHash.getDigestLen();
        byte[] newV = new byte[_seed.length];
        int    newVOffset = 0;
        while (newVOffset + hashLen <= newV.length)
        {
            mHash.digest(tmp, 0, tmp.length, newV, newVOffset);
            plusEquals(tmp, 1);
            newVOffset += hashLen;
        }
        if (newVOffset < newV.length)
        {
            mHash.digest(tmp, 0, tmp.length, tmp, 0);
            System.arraycopy(tmp, 0, newV, newVOffset, newV.length-newVOffset);
        }

        // Assign into V
        java.util.Arrays.fill(V, (byte) 0);
        V = newV;

        // Preallocate a temp buffer large enough to hold V, and
        // large enough to hold a digest.
        int VtmpLen = Math.max(V.length, hashLen);
        if (VtmpLen != Vtmp.length)
          Vtmp = new byte[VtmpLen];

        // Calculate C = Hash(t || newV) mod 2^B
        mHash.update(t, 0, hashLen);
        mHash.update(V, 0, V.length);
        mHash.finishDigest(C, 0);

        // Clean up
        java.util.Arrays.fill(tmp, (byte)0);
    }



    /**
     * Implement the Hash_DRBG algorithm from the X9.82 spec.
     * This implementation does not support any user input.
     */
    public int read()
    {
        byte b[] = new byte[1];
        read(b, 0, 1);
        return b[0] & 0xff;
    }


    /**
     * Implement the Hash_DRBG algorithm from the X9.82 spec.
     * This implementation does not support any user input.
     */
    public int read(
        byte[] out,
        int    offset,
        int    len)
    {
        if (out == null)
          throw new NullPointerException("Output buffer is null");
        if (offset + len > out.length)
          throw new IllegalArgumentException(
              "Writing " + len + " bytes of output starting at offset " +
              offset + " will overrun end of output buffer (" + out.length +
              " bytes long)");
        if (offset < 0)
          throw new IllegalArgumentException(
              "Output array offset is negative (" + offset + ")");
        if (len < 0)
          throw new IllegalArgumentException(
              "Output length is negative (" + len + ")");

        // Generate output bits
        hashGen(out, offset, len);

        // Update State: V = V + C + out[..len] + ctr 
        int suffixOffset = Math.max(offset, offset+len-V.length);
        int suffixLength = Math.min(len, V.length);
        plusEquals(V, C, 0, C.length);
        plusEquals(V, out, suffixOffset, suffixLength);
        plusEquals(V, ctr);

        // Update State: ctr = ctr + 1
        ctr++;

        return len;
    }


    /**
     * Implement the Hashgen subroutine of the X9.82 Hash_DRBG
     * algorithm: calculate H(V) | H(V+1) | H(V+2) | ...
     * until len bytes are generated. Store the result in out[offset...].
     */         
    void hashGen(
        byte[] out,
        int    offset,
        int    len)
    {
        int hashLen = mHash.getDigestLen();

        // Use Vtmp to hold a temp copy of V that will be incremented
        // each time through the loop below. It is also used to
        // temporarily hold the output of the last hash operation
        // where we need only a portion of the output bytes so it must
        // be at least hashLen bytes long
        System.arraycopy(V, 0, Vtmp, 0, V.length);
        while (len > hashLen)
        {
            mHash.digest(Vtmp, 0, V.length, out, offset);
            offset += hashLen;
            len -= hashLen;
            plusEquals(Vtmp, 1);
        }

        // Do the final block
        mHash.digest(Vtmp, 0, V.length, Vtmp, 0);
        System.arraycopy(Vtmp, 0, out, offset, len);
        java.util.Arrays.fill(Vtmp, (byte)0);
    }
    


    /**
     * Add two multi-byte big-endian integers: accum += in[offset..len-1].
     * Overflow is discarded.
     */ 
    void plusEquals(
        byte accum[],
        byte in[],
        int  offset,
        int  len)
    {
        int carry = 0;
        int i=len-1, j=accum.length-1;
        while ((i>=0) && (j>= 0))
        {
            int oldCarry = carry;
            carry = (0xff & accum[j]) + (0xff & in[i]) + carry;
            accum[j] = (byte)carry;
            carry >>= 8;
            j--;
            i--;
        }
    }


    /**
     * Add x to a multi-byte big-endian integer: accum += x.
     * Overflow is discarded.
     */ 
    void plusEquals(
        byte accum[],
        int  x)
    {
        int carry = 0;
        int i=0, j=accum.length-1;
        while ((i<4) && (j>= 0))
        {
            carry = (0xff & accum[j]) + (0xff & x) + carry;
            accum[j] = (byte)carry;
            carry >>= 8;
            j--;
            i--;
            x >>= 8;
        }
    }
    

    /**
     * The underlying hash function driving the PRNG.
     */
    private Digest mHash;

    /**
     * The seed vector, called V in the X9.82 spec. Updated in
     * each call to generate random bytes.
     */
    private byte[] V;

    /**
     * This is a copy of V that is incremented during the internal
     * hashGen method. It is preallocated once per DRBG to avoid
     * the overhead of allocation.
     */
    private byte[] Vtmp;

    /**
     * A constant derived from the seed. Constant for the life of the
     * seed.
     */
    private byte[] C;

    /**
     * A 4-byte counter that is updated with each call to the PRNG.
     */
    private int    ctr;
}
