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

/**
 * This class provides utilities for packing values represented by
 * 16-bit integers into byte arrays, such that the packed elements use
 * only the minimal number of bits in the output stream.
 *
 * <p>For example, given an array of values, each of which is in the
 * range 0..2^9-1, the values could be represented in java as a short
 * (16 bit signed int). but would be packed into the output array
 * using 9 bits per element.
 */
public class BitPack {

    /**
     * Calculate the smallest number of bits necessary to represent a value.
     * <p> For example:
     * <br>val=5  --> return 3  (2^2 <  5 < 2^3)
     * <br>val=17 --> return 5  (2^4 < 17 < 2^5)
     *
     * @param val the value being measured
     * @return the smallest number of bits needed to represent the input value.
     */
    public static final int countBits(
        int val)
    {
        for (int i=0; i<32; i++)
          if ((1<<i) > val)
            return i;
        return 32;
    }
    
    /**
     * Return an integer that can be used to mask off the low numBits
     * of a value.
     * 
     * @param numBits the number of bits to be masked off
     * @return a integer containing a bitmask where the least
     *      significant 'numbits' bits are set (1) and the remaining
     *      bits are clear (0).
     */
    public static final int lowBitMask(int numBits)
    {
        return ~(-1 << numBits);
    }


    /** 
     * Return the number of bytes needed to store the bit-packed
     * output.
     *
     * @param numElts  the number of elements that will be packed.
     * @param maxEltValue a maximal element value, larger than any
     *           input value (typically one larger than the max
     *           input value).
     *
     * @return the number of elements required for the output array,
     *   or 0 on error.
     */
    public final static int pack(
        int   numElts,
        int   maxEltValue)
    {
        return pack(numElts, maxEltValue, null, 0, null, 0);
    }


    /**
     * Bit-pack an array of shorts into a byte array.
     *
     * @param numElts  the number of elements
     * @param maxEltValue a maximal element value, larger than any
     *           input value (typically one larger than the max
     *           input value).
     * @param tgt the destination array.
     * @param tgtOffset the offset into the destination array where the
     *           first element should go.
     * @param src the source array.
     * @param srcOffset the offset into the source array where the
     *            first value should be read from.
     * @return the number of elements used in the output array,
     *   or 0 on error.
     */
    public final static int pack(
        int   numElts,
        int   maxEltValue,
        short src[], int srcOffset,
        byte  tgt[], int tgtOffset)
    {
        // Get the number of bits in each element
        int bitsPerElement = countBits(maxEltValue-1);

        // Get the max output size
        int maxOutLen = (numElts*bitsPerElement+7)/8;

        return pack(numElts, maxEltValue, maxOutLen, src, srcOffset,
                    tgt, tgtOffset);
    }

    /**
     * Bit-pack an array of shorts into a byte array, stopping after
     * a predefined number of bytes have been generated.
     *
     * @param numElts  the number of elements
     * @param maxEltValue a maximal element value, larger than any
     *           input value (typically one larger than the max
     *           input value).
     * @param maxOutLen the maximum number of elements to put into the
     *           destination array.
     * @param tgt the destination array.
     * @param tgtOffset the offset into the destination array where the
     *           first element should go.
     * @param src the source array.
     * @param srcOffset the offset into the source array where the
     *            first value should be read from.
     * @return the number of elements used in the output array,
     *   or 0 on error.
     */
    public final static int pack(
        int   numElts,
        int   maxEltValue,
        int   maxOutLen,
        short src[], int srcOffset,
        byte  tgt[], int tgtOffset)
    {
        if (tgt == null)
          return maxOutLen;

        // Get the number of bits in each element
        int bitsPerElement = countBits(maxEltValue-1);

        int i = srcOffset, iMax = srcOffset + numElts;
        int j = tgtOffset, jMax = tgtOffset + maxOutLen;
        byte cur = 0;
        int next = src[i++];
        int cb = 0, nb = bitsPerElement;
        while ((j < jMax) && ((i < iMax) || (cb+nb > 8)))
        {
            if (cb + nb < 8)
            {
                // Accumulate next into cur. The result will still
                // be less than 8 bits. Then update next will the next
                // input value.
                cur |= (byte) (next << (8 - cb - nb));
                cb += nb;
                next = (0x0ffff & src[i++]); // avoid sign extension
                nb = bitsPerElement;
            }
            else
            {
                // Pull the most significant bits off of next into
                // cur to make cur 8 bits and save it in the output
                // stream. Then clear cur, and mask the used bits out
                // of next.
                int shift = cb + nb - 8;
                int tmp = 0xff & (cur | (next >> shift));
                tgt[j++] = (byte) (cur | (next >> shift));
                cur = 0;
                cb = 0;
                next &= lowBitMask(shift);
                nb = shift;
            }
        }

        if (j<jMax)
          tgt[j++] = (byte) (next << (8 - nb));

        return (j-tgtOffset);
    }


    /**
     * Calculate the number of input bytes that would be consumed decoding
     * a bit-packed array. 
     *
     * @param numElts the number of elements to decode
     * @param maxEltValue the maximum value that can appear in the array.
     *     This value is used to derive the number of bits per element
     *     in the packed representation.
     * @return the number of input bytes that would be consumed,
     *   or 0 on error.
     */
    public final static int unpack(
        int   numElts,
        int   maxEltValue)
    {
        return unpack(numElts, maxEltValue, null, 0, null, 0);
    }


    /**
     * Unpack a bit-packed array into an array of shorts. The number of bits
     * per element is implied by maxEltValue.
     *
     * @param numElts the number of elements to decode
     * @param maxEltValue the maximum value that can appear in the array.
     *     This value is used to derive the number of bits per element
     *     in the packed representation.
     * @param src the bit-packed input.
     * @param srcOffset the offset into the source array of the first
     *     element to be unpacked.
     * @param tgt the destination array
     * @param tgtOffset the offset into the destination array in which
     *     to start storing data.
     * @return the number of input bytes that were consumed,
     *   or 0 on error.
     */
    public final static int unpack(
        int   numElts,
        int   maxEltValue,
        byte  src[], int srcOffset,
        short tgt[], int tgtOffset)
    {
        // Get the number of bits in each element
        int bitsPerElement = countBits(maxEltValue-1);

        // Get the max output size
        int maxUsed = (numElts*bitsPerElement+7)/8;
        if (tgt == null)
          return maxUsed;

        // i and j are the indices into the source and destination.
        int i = srcOffset, iMax = srcOffset + maxUsed;
        int j = tgtOffset, jMax = tgtOffset + numElts;

        // tmp holds up to 16 bits from the source stream.
        // Stored as an int to make it easier to shift bits.
        int tmp = (0xff & src[i++]);
        // tb holds the number of bits in tmp that are valid,
        // that is, that still need to be placed in the tgt array.
        // These will always be the least significant bits of tmp.
        int tb = 8;
        // ob holds the number of bits in the last output byte
        // (tgt[j]) that are valid. This counts from the most-
        // significant relevant bit in tgt. So if bitsPerElement
        // is 10, and ob is 7, then bits 9-3 are filled and bits
        // 0-2 remain to be filled.
        int ob = 0;
        tgt[j] = 0;
        while ((i < iMax) || (ob + tb >= bitsPerElement))
        {
            if (ob + tb < bitsPerElement)
            {
                // Adding tb bits from tmp to the ob bits in tgt[j]
                // will not overflow the output element tgt[j].
                // Move all tb bits from tmp into tgt[j].
                int shift = bitsPerElement - ob - tb;
                tgt[j] |= (short) ((tmp << shift) & 0x00ffff);
                ob += tb;
                tmp = (0xff & src[i++]);
                tb = 8;
            }
            else
            {
                // tmp has more bits than we need to finish output
                // element tgt[j]. Move some of the bits from tmp to
                // tgt[j] to finish it off, and save the leftovers in
                // tmp for the next iteration of the loop when we start
                // to fill in tgt[j+1].
                int shift = ob + tb - bitsPerElement;
                tgt[j++] |= (short) (((tmp & 0xff)>> shift) & 0x00ff);
                if (j < jMax) tgt[j] = 0;
                ob = 0;
                tmp &= lowBitMask(shift);
                tb = shift;
            }
        }

        return maxUsed;
    }
}
