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

/**
 * This class implements the SHA-1 message digest algorithm.
 */
class Sha1 extends Digest 
{
    /**
     * Constructor.
     */
    public Sha1()
    {
        reset();
    }

    /**
     * Get the length of the hash output, in bytes.
     * For SHA-1, this will always return 20.
     */
    public int getDigestLen()
    {
        return HASH_LEN;
    }

    /**
     * Get the size of the input block for the core hash algorithm, in bytes.
     * For SHA-1, this will always return 64.
     */
    public int getBlockLen()
    {
        return BLOCK_LEN;
    }


    /**
     * Reinitialize the digest operation, discarding any internal state.
     */
    public void reset()
    {
        java.util.Arrays.fill(buf, (byte)0);
        bufOff = 0;
        byteCount = 0;
        state[0] = 0x67452301;
        state[1] = 0xefcdab89;
        state[2] = 0x98badcfe;
        state[3] = 0x10325476;
        state[4] = 0xc3d2e1f0;
    }


    /**
     * Updates the message digest with new data.
     *
     * @param data      the data to be added.
     * @param offset    the start of the data in the array.
     * @param length    the number of bytes of data to add.
     */
    public void update(byte[] data, int offset, int length)
    {
        // Sanity check inputs
        if (data == null)
          throw new NullPointerException("Input data buffer is null");
        if (offset + length > data.length)
          throw new IllegalArgumentException(
              "reading " + length + " bytes of input starting at offset " +
              offset + " will overrun end of input buffer (" + data.length +
              " bytes long)");
        if (offset < 0)
          throw new IllegalArgumentException(
              "input offset is negative (" + offset + ")");
        if (length < 0)
          throw new IllegalArgumentException(
              "input length is negative (" + offset + ")");

        byteCount += length;

        // Process any full blocks we get by combining cached input
        // with the new input
        while (bufOff + length >= buf.length)
        {
            int todo = buf.length - bufOff;
            System.arraycopy(data, offset, buf, bufOff, todo);
            transform(buf);
            length -= todo;
            offset += todo;
            bufOff = 0;
        }

        // Copy any extra data into the cached input buffer.
        System.arraycopy(data, offset, buf, bufOff, length);
        bufOff += length;
    }


    
    /**
     * Completes the digest calculation and returns the result in the
     * supplied array. The output will be <code>getDigestLen()</code>
     * bytes long. The object is reinialized (see
     * <code>reset()</code>).
     */
    public void finishDigest(
        byte[] out,
        int    outOffset)
    {
        // Sanity check inputs
        if (out == null)
          throw new NullPointerException("output array is null");
        if (outOffset + getDigestLen() > out.length)
          throw new IllegalArgumentException(
              "output array is too short: start at offset " + outOffset +
              " and writing " + getDigestLen() + " bytes will overrun " +
              " buffer length " + out.length);
        if (outOffset < 0)
          throw new IllegalArgumentException(
              "output offset is negative (" + outOffset + ")");

        // Add the "end of input" marker
        buf[bufOff++] = (byte)0x80;
        
        // If the current block is not large enough to hold the
        // 8-byte long bitcount, pad the current block with 0s,
        // process it, and start a new block.
        if (bufOff + 8 > buf.length) {
            java.util.Arrays.fill(buf, bufOff, getBlockLen(), (byte)0);
            transform(buf);
            bufOff = 0;
        }
        
        // Pad the final block with 0's, then the bitcount of all of the input
        java.util.Arrays.fill(buf, bufOff, buf.length-8, (byte)0);
        long bitCount = byteCount * 8;
        for (int i=0; i<8; i++)
        {
            buf[buf.length - i - 1] = (byte) bitCount;
            bitCount >>>= 8;
        }

        // Process the final block
        transform(buf);

        // Copy the result to the output buffer.
        int2byte(state, 0, out, outOffset, state.length);

        // Reset the object
        reset();
    }



    // SHA-1 block routines
    //......................................................................

    /** The buffer used to store the last incomplete block. */
    private byte[] buf = new byte[BLOCK_LEN];

    /** The number of bytes currently stored in <code>buf</code>. */
    private int bufOff;

    /** The number of bytes that have been input to the digest. */
    private long byteCount;

    private static final long MAXCNT = (1L << 61)-1L;

    /** Length of the final hash (in bytes). */
    static final int HASH_LEN = 20;

    /** Length of the intermediate blocks */
    static final int BLOCK_LEN = 64;

    /** 5 32-bit words (interim result) */
    private int[] state = new int[HASH_LEN/4];

    /**
     * A temporary buffer used by the transform() routine 
     * It is allocated once per object to reduce the cost of allocation.
     */
    private int[] data = new int[16];
    private int[] w = new int[16];


    /**
     * Convert an array of bytes into an array of 32-bit integers.
     * Each output integer uses 4 input bytes. The number of input
     * bytes must be a multiple of 4.
     */
    private static void byte2int(
        byte[] src, int srcOffset,
        int[]  dst, int dstOffset,
        int    numInts)
    {
        while (numInts-- > 0)
        {
            // Big endian
            dst[dstOffset++] = ((src[srcOffset++] << 24) |
                                ((src[srcOffset++] & 0xFF) << 16) |
                                ((src[srcOffset++] & 0xFF) <<  8) |
                                (src[srcOffset++] & 0xFF));
        }
    }

    /**
     * Convert an integer array into an byte array using the
     * big-endian encoing of the integers.
     */
    protected void int2byte(
        int[]  src, int srcOffset,
        byte[] dst, int dstOffset,
        int    numInts)
    {
        int end = numInts + srcOffset;
        for (int i=srcOffset, j=dstOffset; i<end; i++)
        {
            int d = src[srcOffset+i];
            dst[j++] = (byte)(d >>> 24);
            dst[j++] = (byte)(d >>> 16);
            dst[j++] = (byte)(d >>> 8);
            dst[j++] = (byte)(d);
        }
    }

    private static final int RL(int a, int n)
    {
        return ((a<<n) | (a >>> (32-n)));
    }


    private static final int K00_19 = 0x5a827999;
    private static final int K20_39 = 0x6ed9eba1;
    private static final int K40_59 = 0x8f1bbcdc;
    private static final int K60_79 = 0xca62c1d6;

    void transform(
        byte X[])
    {
        byte2int(X, 0, data, 0, 16);

        int A, B, C, D, E;

        /* init A - E */

        A = state[0]; 
        B = state[1];
        C = state[2];
        D = state[3];
        E = state[4];

        /* rounds 0 - 15 */

        E += RL(A, 5) + K00_19 + (B & (C ^ D) ^ D) + data[ 0]; B = RL(B, 30);
        D += RL(E, 5) + K00_19 + (A & (B ^ C) ^ C) + data[ 1]; A = RL(A, 30);
        C += RL(D, 5) + K00_19 + (E & (A ^ B) ^ B) + data[ 2]; E = RL(E, 30);
        B += RL(C, 5) + K00_19 + (D & (E ^ A) ^ A) + data[ 3]; D = RL(D, 30);
        A += RL(B, 5) + K00_19 + (C & (D ^ E) ^ E) + data[ 4]; C = RL(C, 30);
        E += RL(A, 5) + K00_19 + (B & (C ^ D) ^ D) + data[ 5]; B = RL(B, 30);
        D += RL(E, 5) + K00_19 + (A & (B ^ C) ^ C) + data[ 6]; A = RL(A, 30);
        C += RL(D, 5) + K00_19 + (E & (A ^ B) ^ B) + data[ 7]; E = RL(E, 30);
        B += RL(C, 5) + K00_19 + (D & (E ^ A) ^ A) + data[ 8]; D = RL(D, 30);
        A += RL(B, 5) + K00_19 + (C & (D ^ E) ^ E) + data[ 9]; C = RL(C, 30);
        E += RL(A, 5) + K00_19 + (B & (C ^ D) ^ D) + data[10]; B = RL(B, 30);
        D += RL(E, 5) + K00_19 + (A & (B ^ C) ^ C) + data[11]; A = RL(A, 30);
        C += RL(D, 5) + K00_19 + (E & (A ^ B) ^ B) + data[12]; E = RL(E, 30);
        B += RL(C, 5) + K00_19 + (D & (E ^ A) ^ A) + data[13]; D = RL(D, 30);
        A += RL(B, 5) + K00_19 + (C & (D ^ E) ^ E) + data[14]; C = RL(C, 30);
        E += RL(A, 5) + K00_19 + (B & (C ^ D) ^ D) + data[15]; B = RL(B, 30);

        /* rounds 16 - 19 */

        w[ 0] = data[ 0] ^ data[ 2] ^ data[ 8] ^ data[13]; w[ 0] = RL(w[0], 1);
        D += RL(E, 5) + K00_19 + (A & (B ^ C) ^ C) + w[ 0]; A = RL(A, 30);
        w[ 1] = data[ 1] ^ data[ 3] ^ data[ 9] ^ data[14]; w[ 1] = RL(w[1], 1);
        C += RL(D, 5) + K00_19 + (E & (A ^ B) ^ B) + w[ 1]; E = RL(E, 30);
        w[ 2] = data[ 2] ^ data[ 4] ^ data[10] ^ data[15]; w[ 2] = RL(w[ 2], 1);
        B += RL(C, 5) + K00_19 + (D & (E ^ A) ^ A) + w[ 2]; D = RL(D, 30);
        w[ 3] = data[ 3] ^ data[ 5] ^ data[11] ^ w[ 0]; w[ 3] = RL(w[ 3], 1);
        A += RL(B, 5) + K00_19 + (C & (D ^ E) ^ E) + w[ 3]; C = RL(C, 30);

        /* rounds 20 - 39 */

        w[ 4] = data[ 4] ^ data[ 6] ^ data[12] ^ w[ 1]; w[ 4] = RL(w[ 4], 1);
        E += RL(A, 5) + K20_39 + (B ^ C ^ D) + w[ 4]; B = RL(B, 30);
        w[ 5] = data[ 5] ^ data[ 7] ^ data[13] ^ w[ 2]; w[ 5] = RL(w[ 5], 1);
        D += RL(E, 5) + K20_39 + (A ^ B ^ C) + w[ 5]; A = RL(A, 30);
        w[ 6] = data[ 6] ^ data[ 8] ^ data[14] ^ w[ 3]; w[ 6] = RL(w[ 6], 1);
        C += RL(D, 5) + K20_39 + (E ^ A ^ B) + w[ 6]; E = RL(E, 30);
        w[ 7] = data[ 7] ^ data[ 9] ^ data[15] ^ w[ 4]; w[ 7] = RL(w[ 7], 1);
        B += RL(C, 5) + K20_39 + (D ^ E ^ A) + w[ 7]; D = RL(D, 30);
        w[ 8] = data[ 8] ^ data[10] ^ w[ 0] ^ w[ 5]; w[ 8] = RL(w[ 8], 1);
        A += RL(B, 5) + K20_39 + (C ^ D ^ E) + w[ 8]; C = RL(C, 30);
        w[ 9] = data[ 9] ^ data[11] ^ w[ 1] ^ w[ 6]; w[ 9] = RL(w[ 9], 1);
        E += RL(A, 5) + K20_39 + (B ^ C ^ D) + w[ 9]; B = RL(B, 30);
        w[10] = data[10] ^ data[12] ^ w[ 2] ^ w[ 7]; w[10] = RL(w[10], 1);
        D += RL(E, 5) + K20_39 + (A ^ B ^ C) + w[10]; A = RL(A, 30);
        w[11] = data[11] ^ data[13] ^ w[ 3] ^ w[ 8]; w[11] = RL(w[11], 1);
        C += RL(D, 5) + K20_39 + (E ^ A ^ B) + w[11]; E = RL(E, 30);
        w[12] = data[12] ^ data[14] ^ w[ 4] ^ w[ 9]; w[12] = RL(w[12], 1);
        B += RL(C, 5) + K20_39 + (D ^ E ^ A) + w[12]; D = RL(D, 30);
        w[13] = data[13] ^ data[15] ^ w[ 5] ^ w[10]; w[13] = RL(w[13], 1);
        A += RL(B, 5) + K20_39 + (C ^ D ^ E) + w[13]; C = RL(C, 30);
        w[14] = data[14] ^ w[ 0] ^ w[ 6] ^ w[11]; w[14] = RL(w[14], 1);
        E += RL(A, 5) + K20_39 + (B ^ C ^ D) + w[14]; B = RL(B, 30);
        w[15] = data[15] ^ w[ 1] ^ w[ 7] ^ w[12]; w[15] = RL(w[15], 1);
        D += RL(E, 5) + K20_39 + (A ^ B ^ C) + w[15]; A = RL(A, 30);
        w[ 0] = w[ 0] ^ w[ 2] ^ w[ 8] ^ w[13]; w[ 0] = RL(w[ 0], 1);
        C += RL(D, 5) + K20_39 + (E ^ A ^ B) + w[ 0]; E = RL(E, 30);
        w[ 1] = w[ 1] ^ w[ 3] ^ w[ 9] ^ w[14]; w[ 1] = RL(w[ 1], 1);
        B += RL(C, 5) + K20_39 + (D ^ E ^ A) + w[ 1]; D = RL(D, 30);
        w[ 2] = w[ 2] ^ w[ 4] ^ w[10] ^ w[15]; w[ 2] = RL(w[ 2], 1);
        A += RL(B, 5) + K20_39 + (C ^ D ^ E) + w[ 2]; C = RL(C, 30);
        w[ 3] = w[ 3] ^ w[ 5] ^ w[11] ^ w[ 0]; w[ 3] = RL(w[ 3], 1);
        E += RL(A, 5) + K20_39 + (B ^ C ^ D) + w[ 3]; B = RL(B, 30);
        w[ 4] = w[ 4] ^ w[ 6] ^ w[12] ^ w[ 1]; w[ 4] = RL(w[ 4], 1);
        D += RL(E, 5) + K20_39 + (A ^ B ^ C) + w[ 4]; A = RL(A, 30);
        w[ 5] = w[ 5] ^ w[ 7] ^ w[13] ^ w[ 2]; w[ 5] = RL(w[ 5], 1);
        C += RL(D, 5) + K20_39 + (E ^ A ^ B) + w[ 5]; E = RL(E, 30);
        w[ 6] = w[ 6] ^ w[ 8] ^ w[14] ^ w[ 3]; w[ 6] = RL(w[ 6], 1);
        B += RL(C, 5) + K20_39 + (D ^ E ^ A) + w[ 6]; D = RL(D, 30);
        w[ 7] = w[ 7] ^ w[ 9] ^ w[15] ^ w[ 4]; w[ 7] = RL(w[ 7], 1);
        A += RL(B, 5) + K20_39 + (C ^ D ^ E) + w[ 7]; C = RL(C, 30);

        /* rounds 40 - 59 */

        w[ 8] = w[ 8] ^ w[10] ^ w[ 0] ^ w[ 5]; w[ 8] = RL(w[ 8], 1);
        E += RL(A, 5) + K40_59 + ((B & C) | (D & (B | C))) + w[ 8]; B = RL(B, 30);
        w[ 9] = w[ 9] ^ w[11] ^ w[ 1] ^ w[ 6]; w[ 9] = RL(w[ 9], 1);
        D += RL(E, 5) + K40_59 + ((A & B) | (C & (A | B))) + w[ 9]; A = RL(A, 30);
        w[10] = w[10] ^ w[12] ^ w[ 2] ^ w[ 7]; w[10] = RL(w[10], 1);
        C += RL(D, 5) + K40_59 + ((E & A) | (B & (E | A))) + w[10]; E = RL(E, 30);
        w[11] = w[11] ^ w[13] ^ w[ 3] ^ w[ 8]; w[11] = RL(w[11], 1);
        B += RL(C, 5) + K40_59 + ((D & E) | (A & (D | E))) + w[11]; D = RL(D, 30);
        w[12] = w[12] ^ w[14] ^ w[ 4] ^ w[ 9]; w[12] = RL(w[12], 1);
        A += RL(B, 5) + K40_59 + ((C & D) | (E & (C | D))) + w[12]; C = RL(C, 30);
        w[13] = w[13] ^ w[15] ^ w[ 5] ^ w[10]; w[13] = RL(w[13], 1);
        E += RL(A, 5) + K40_59 + ((B & C) | (D & (B | C))) + w[13]; B = RL(B, 30);
        w[14] = w[14] ^ w[ 0] ^ w[ 6] ^ w[11]; w[14] = RL(w[14], 1);
        D += RL(E, 5) + K40_59 + ((A & B) | (C & (A | B))) + w[14]; A = RL(A, 30);
        w[15] = w[15] ^ w[ 1] ^ w[ 7] ^ w[12]; w[15] = RL(w[15], 1);
        C += RL(D, 5) + K40_59 + ((E & A) | (B & (E | A))) + w[15]; E = RL(E, 30);
        w[ 0] = w[ 0] ^ w[ 2] ^ w[ 8] ^ w[13]; w[ 0] = RL(w[ 0], 1);
        B += RL(C, 5) + K40_59 + ((D & E) | (A & (D | E))) + w[ 0]; D = RL(D, 30);
        w[ 1] = w[ 1] ^ w[ 3] ^ w[ 9] ^ w[14]; w[ 1] = RL(w[ 1], 1);
        A += RL(B, 5) + K40_59 + ((C & D) | (E & (C | D))) + w[ 1]; C = RL(C, 30);
        w[ 2] = w[ 2] ^ w[ 4] ^ w[10] ^ w[15]; w[ 2] = RL(w[ 2], 1);
        E += RL(A, 5) + K40_59 + ((B & C) | (D & (B | C))) + w[ 2]; B = RL(B, 30);
        w[ 3] = w[ 3] ^ w[ 5] ^ w[11] ^ w[ 0]; w[ 3] = RL(w[ 3], 1);
        D += RL(E, 5) + K40_59 + ((A & B) | (C & (A | B))) + w[ 3]; A = RL(A, 30);
        w[ 4] = w[ 4] ^ w[ 6] ^ w[12] ^ w[ 1]; w[ 4] = RL(w[ 4], 1);
        C += RL(D, 5) + K40_59 + ((E & A) | (B & (E | A))) + w[ 4]; E = RL(E, 30);
        w[ 5] = w[ 5] ^ w[ 7] ^ w[13] ^ w[ 2]; w[ 5] = RL(w[ 5], 1);
        B += RL(C, 5) + K40_59 + ((D & E) | (A & (D | E))) + w[ 5]; D = RL(D, 30);
        w[ 6] = w[ 6] ^ w[ 8] ^ w[14] ^ w[ 3]; w[ 6] = RL(w[ 6], 1);
        A += RL(B, 5) + K40_59 + ((C & D) | (E & (C | D))) + w[ 6]; C = RL(C, 30);
        w[ 7] = w[ 7] ^ w[ 9] ^ w[15] ^ w[ 4]; w[ 7] = RL(w[ 7], 1);
        E += RL(A, 5) + K40_59 + ((B & C) | (D & (B | C))) + w[ 7]; B = RL(B, 30);
        w[ 8] = w[ 8] ^ w[10] ^ w[ 0] ^ w[ 5]; w[ 8] = RL(w[ 8], 1);
        D += RL(E, 5) + K40_59 + ((A & B) | (C & (A | B))) + w[ 8]; A = RL(A, 30);
        w[ 9] = w[ 9] ^ w[11] ^ w[ 1] ^ w[ 6]; w[ 9] = RL(w[ 9], 1);
        C += RL(D, 5) + K40_59 + ((E & A) | (B & (E | A))) + w[ 9]; E = RL(E, 30);
        w[10] = w[10] ^ w[12] ^ w[ 2] ^ w[ 7]; w[10] = RL(w[10], 1);
        B += RL(C, 5) + K40_59 + ((D & E) | (A & (D | E))) + w[10]; D = RL(D, 30);
        w[11] = w[11] ^ w[13] ^ w[ 3] ^ w[ 8]; w[11] = RL(w[11], 1);
        A += RL(B, 5) + K40_59 + ((C & D) | (E & (C | D))) + w[11]; C = RL(C, 30);

        /* rounds 60 - 79 */

        w[12] = w[12] ^ w[14] ^ w[ 4] ^ w[ 9]; w[12] = RL(w[12], 1);
        E += RL(A, 5) + K60_79 + (B ^ C ^ D) + w[12]; B = RL(B, 30);
        w[13] = w[13] ^ w[15] ^ w[ 5] ^ w[10]; w[13] = RL(w[13], 1);
        D += RL(E, 5) + K60_79 + (A ^ B ^ C) + w[13]; A = RL(A, 30);
        w[14] = w[14] ^ w[ 0] ^ w[ 6] ^ w[11]; w[14] = RL(w[14], 1);
        C += RL(D, 5) + K60_79 + (E ^ A ^ B) + w[14]; E = RL(E, 30);
        w[15] = w[15] ^ w[ 1] ^ w[ 7] ^ w[12]; w[15] = RL(w[15], 1);
        B += RL(C, 5) + K60_79 + (D ^ E ^ A) + w[15]; D = RL(D, 30);
        w[ 0] = w[ 0] ^ w[ 2] ^ w[ 8] ^ w[13]; w[ 0] = RL(w[ 0], 1);
        A += RL(B, 5) + K60_79 + (C ^ D ^ E) + w[ 0]; C = RL(C, 30);
        w[ 1] = w[ 1] ^ w[ 3] ^ w[ 9] ^ w[14]; w[ 1] = RL(w[ 1], 1);
        E += RL(A, 5) + K60_79 + (B ^ C ^ D) + w[ 1]; B = RL(B, 30);
        w[ 2] = w[ 2] ^ w[ 4] ^ w[10] ^ w[15]; w[ 2] = RL(w[ 2], 1);
        D += RL(E, 5) + K60_79 + (A ^ B ^ C) + w[ 2]; A = RL(A, 30);
        w[ 3] = w[ 3] ^ w[ 5] ^ w[11] ^ w[ 0]; w[ 3] = RL(w[ 3], 1);
        C += RL(D, 5) + K60_79 + (E ^ A ^ B) + w[ 3]; E = RL(E, 30);
        w[ 4] = w[ 4] ^ w[ 6] ^ w[12] ^ w[ 1]; w[ 4] = RL(w[ 4], 1);
        B += RL(C, 5) + K60_79 + (D ^ E ^ A) + w[ 4]; D = RL(D, 30);
        w[ 5] = w[ 5] ^ w[ 7] ^ w[13] ^ w[ 2]; w[ 5] = RL(w[ 5], 1);
        A += RL(B, 5) + K60_79 + (C ^ D ^ E) + w[ 5]; C = RL(C, 30);
        w[ 6] = w[ 6] ^ w[ 8] ^ w[14] ^ w[ 3]; w[ 6] = RL(w[ 6], 1);
        E += RL(A, 5) + K60_79 + (B ^ C ^ D) + w[ 6]; B = RL(B, 30);
        w[ 7] = w[ 7] ^ w[ 9] ^ w[15] ^ w[ 4]; w[ 7] = RL(w[ 7], 1);
        D += RL(E, 5) + K60_79 + (A ^ B ^ C) + w[ 7]; A = RL(A, 30);
        w[ 8] = w[ 8] ^ w[10] ^ w[ 0] ^ w[ 5]; w[ 8] = RL(w[ 8], 1);
        C += RL(D, 5) + K60_79 + (E ^ A ^ B) + w[ 8]; E = RL(E, 30);
        w[ 9] = w[ 9] ^ w[11] ^ w[ 1] ^ w[ 6]; w[ 9] = RL(w[ 9], 1);
        B += RL(C, 5) + K60_79 + (D ^ E ^ A) + w[ 9]; D = RL(D, 30);
        w[10] = w[10] ^ w[12] ^ w[ 2] ^ w[ 7]; w[10] = RL(w[10], 1);
        A += RL(B, 5) + K60_79 + (C ^ D ^ E) + w[10]; C = RL(C, 30);
        w[11] = w[11] ^ w[13] ^ w[ 3] ^ w[ 8]; w[11] = RL(w[11], 1);
        E += RL(A, 5) + K60_79 + (B ^ C ^ D) + w[11]; B = RL(B, 30);
        w[12] = w[12] ^ w[14] ^ w[ 4] ^ w[ 9]; w[12] = RL(w[12], 1);
        D += RL(E, 5) + K60_79 + (A ^ B ^ C) + w[12]; A = RL(A, 30);
        w[13] = w[13] ^ w[15] ^ w[ 5] ^ w[10];
        C += RL(D, 5) + K60_79 + (E ^ A ^ B) + RL(w[13], 1); E = RL(E, 30);
        w[14] = w[14] ^ w[ 0] ^ w[ 6] ^ w[11];
        B += RL(C, 5) + K60_79 + (D ^ E ^ A) + RL(w[14], 1); D = RL(D, 30);

        /* update H0 - H4 */

        w[15] = w[15] ^ w[ 1] ^ w[ 7] ^ w[12];
        state[0] += A + RL(B, 5) + K60_79 + (C ^ D ^ E) + RL(w[15], 1);
        state[1] += B;
        state[2] += RL(C, 30);
        state[3] += D;
        state[4] += E;

        /* clear temp variables */
        A = B = C = D = E = 0;
        java.util.Arrays.fill(w, 0);
        java.util.Arrays.fill(data, 0);
    }
}

