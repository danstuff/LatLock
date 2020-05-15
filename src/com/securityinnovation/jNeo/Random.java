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

package com.securityinnovation.jNeo;

import static com.securityinnovation.jNeo.digest.DigestAlgorithm.*;
import com.securityinnovation.jNeo.inputstream.X982Drbg;


/**
 * <p>This is the PRNG for jNeo. It is based on the X9.82 DRBG algorithm
 * "Hash Function DRBG Using Any Approved Hash Function (Hash_DRBG)"
 * using SHA-256 as the underlying hash.
 *
 * <p>This implementation uses the following value for t:
 * <br> 0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54,
 * <br> 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05,
 * <br> 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c,
 * <br> 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
 * <br> 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9,
 * <br> 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a,
 * <br> 0xf9, 0x27, 0xda, 0x3e
 *
 * <p>This implementation does not enforce the seed length
 * requirements specified in the X9.82 documentation, but in all cases
 * the seed must be non-null.
 */
public class Random
{
    /**
     * Constructor that initializes the PRNG with the supplied seed.
     *
     * @param _seed the new seed for the PRNG.
     */
    public Random(
        byte _seed[])
    {
        if (_seed == null)
          throw new NullPointerException("seed is null");
        rng = new X982Drbg(sha256, _seed);
    }

    
    /**
     * Reinitialize the jNeo PRNG with the supplied seed. This discards
     * the old PRNG state.
     *
     * @param _seed the new seed for the PRNG. This must be non-null.
     */
    public void seed(
        byte[] _seed)
    {
        if (_seed == null)
          throw new NullPointerException("seed is null");
        rng.seed(_seed);
    }


    /**
     * Reseed the jNeo PRNG with the supplied seed. This combines the
     * seed into the existing PRNG state.
     *
     * @param _seed the value to integrate into the PRNG state. This
     *              must be non-null.
     */
    public void reseed(
        byte[] _seed)
    {
        if (_seed == null)
          throw new NullPointerException("seed is null");
        rng.reseed(_seed);
    }


    /**
     * Read bytes from the random number stream into an array.
     * 
     * @param outbuf the buffer to store the output into.
     * @param offset the offset to start storing the data at.
     * @param length the number of bytes to output.
     */
    public void read(
        byte outbuf[],
        int  offset,
        int  length)
    {
        rng.read(outbuf, offset, length);
    }


    /**
     * Fill an array with bytes from the PRNG stream.
     * This is identical to read(outbuf, 0, outbuf.length);
     * 
     * @param outbuf the buffer to store the output into.
     */
    public void read(
        byte outbuf[])
    {
        rng.read(outbuf, 0, outbuf.length);
    }


    /**
     * The PRNG.
     */
    X982Drbg rng;
}
