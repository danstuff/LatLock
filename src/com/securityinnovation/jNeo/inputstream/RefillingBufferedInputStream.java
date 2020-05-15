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
import java.io.IOException;

/**
 * <p>This class buffers the output of an InputStream. It is parameterized
 * by an InputStream that it wraps and a buffer length.
 *
 * <p>This differs from the standard java.io.BufferedInputStream in
 * that the standard BIS reads n bytes of input from its wrapped
 * input, and when that is consumed it consistently returns 0. This class,
 * on the other hand, reads n bytes of input from the wrapped input,
 * doles it out, and when it is all consumed it will request another
 * n bytes of input from the wrapped InputStream. 
 *
 * <p>This class was written to buffer the output of the X9.82 DRBG.
 * The DRBG is defined to hash its internal state to produce the
 * output stream and discard any hash output in excess of the
 * requested length. This results in unnecessary hash calculations,
 * especially when many small requests are made. Wrapping the X9.82 in
 * a RefillingBufferedInputStream and setting the buffer size to the
 * size of the underlying hash algorithm will eliminate this waste.
 */
public class RefillingBufferedInputStream extends InputStream
{
    InputStream is;
    int         next;
    byte        buf[];

    /**
     * Constructor.
     *
     * @param in   the underlying input stream.
     * @param size the buffer size.
     */
    RefillingBufferedInputStream(
        InputStream in,
        int         size)
    {
        is = in;
        buf = new byte[size];
        next = buf.length;
    }


    /**
     * Returns the next byte of input.
     */
    public int read()
        throws IOException
    {
        if (next >= buf.length)
          refill();
        return (0xff & buf[next++]);
    }


    /**
     * Reads bytes from this byte-input stream into the specified byte
     * array, starting at the given offset.
     *
     * @param b   destination buffer.
     * @param off offset at which to start storing bytes.
     * @param len maximum number of bytes to read.
     *
     * See the parallel <code>read</code> method in
     * <code>InputStream</code>.
     */
    public int read(byte[] b, int off, int len)
        throws IOException
    {
        int origLen = len;
        while (len > 0)
        {
            if (next >= buf.length)
              refill();
            int count = Math.min(len, buf.length-next);
            System.arraycopy(buf, next, b, off, count);
            off += count;
            len -= count;
            next += count;
        }

        return origLen;
    }


    /**
     * Actually read the next block of data from the underlying stream.
     */
    void refill()
        throws IOException
    {
        is.read(buf);
        next = 0;
    }
}
