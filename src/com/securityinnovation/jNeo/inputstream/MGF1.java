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
import com.securityinnovation.jNeo.digest.Digest;

/**
 * This InputStream derivative generates its output based on the MGF-1
 * algorithm defined in the PKCS#1 spec.
 */
public class MGF1 extends InputStream
{
    /**
     * The MGF seed concatenated with the 4-byte MGF counter.
     */
    private byte seedAndCounter[];

    /**
     * The underlying hash algorithm.
     */
    private Digest hash;

    /**
     * State to hold the generated output that has not been returned yet.
     */
    private byte outputStream[];

    /**
     * The index of the first unreturned byte in outputStream.
     */
    private int  outputUsed;

    /**
     * The minimum number of times the underlying hash algorithm should
     * be run.
     */
    private int  minNumRuns;

    /**
     * The number of times the underlying hash algorithm has been run
     * so far.
     */
    private int  numRuns;



    /**
     * Initialize the MGF with a seed.
     * @param hashAlg  identifies the hash algorithm underlying the MGF
     * @param _minNumRuns the minimum number of times the hash algorithm
     *            should be run. If the hash algorithm has not been run
     *            this many times before the MGF is close()ed, then
     *            during the close() the hash will be calculated enough
     *            times to bring the total count up to minNumRuns.
     * @param hashSeed a flag indicating whether the seed needs to be
     *            hashed before use. Typically this will be true if the
     *            seed length is greater than the block size of the
     *            underlying hash algorithm.
     * @param seed the array containing the MGF seed.
     * @param seedOffset the index of the start of the seed within the
     *            seed array.
     * @param seedLength the length of the seed.
     */
    public MGF1(
        DigestAlgorithm hashAlg,
        int             _minNumRuns,
        boolean         hashSeed,
        byte            seed[], int seedOffset, int seedLength)
    {
        hash = hashAlg.newInstance();

        minNumRuns = _minNumRuns;

        if (hashSeed)
        {
            seedAndCounter = new byte[hash.getDigestLen() + 4];
            hash.digest(seed, 0, seedLength, seedAndCounter, 0);
            seedLength = hash.getDigestLen();
        }
        else
        {
            seedAndCounter = new byte[seedLength + 4];
            System.arraycopy(seed, seedOffset, seedAndCounter, 0, seedLength);
        }
        seedAndCounter[seedLength]   = 0;
        seedAndCounter[seedLength+1] = 0;
        seedAndCounter[seedLength+2] = 0;
        seedAndCounter[seedLength+3] = 0;

        outputStream = new byte[hash.getDigestLen()];
        outputUsed = outputStream.length;
    }


    /**
     * Closes this input stream. By the time this call returns the
     * underlying hash function will have been called minNumRuns times
     * (see constructor)
     */
    public void close()
    {
        while (numRuns < minNumRuns)
          fillBuffer();

        outputStream = null;
        seedAndCounter = null;
        hash = null;
    }

    /**
     * Returns the next byte of data from the MGF-1 calculation.
     */
    public int read()
    {
        if (outputUsed >= outputStream.length)
          fillBuffer();
        return 0xff & outputStream[outputUsed++];
    }


    /**
     * Returns the next len bytes of data from the MGF-1 calculation.
     */
    public int read(byte[] out, int offset, int len)
    {
        int toread = len;
        while (toread > 0)
        {
            if (outputUsed >= outputStream.length)
              fillBuffer();
            
            int n = Math.min(outputStream.length - outputUsed, toread);
            System.arraycopy(outputStream, outputUsed, out, offset, n);
            outputUsed += n;
            offset += n;
            toread -=n;
        }
        return len;
    }


    /**
     * Update the internal state with the next block of output from
     * the underlying hash algorithm..
     */
    private void fillBuffer()
    {
        numRuns++;
        outputUsed = 0;
        hash.digest(seedAndCounter, 0, seedAndCounter.length, outputStream, 0);

        // Increment the counter
        int carry = 1;
        for (int i=seedAndCounter.length-1; i>seedAndCounter.length-5; i--)
        {
            int x = (seedAndCounter[i] & 0xff) + carry;
            seedAndCounter[i] = (byte) (x & 0xff);
            carry = (x >> 8);
        }
    }
}
