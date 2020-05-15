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

import org.junit.Test;
import static org.junit.Assert.*;

import java.io.IOException;
import java.io.InputStream;

public class RefillingBufferedInputStreamTestCase {

    // This class produces an incrementing series of integers,
    // except that at the end of each call the internal counter 
    // is raised to the next multiple of 10.
    class SkippingInputStream extends InputStream
    {
        int c = 10;
        public int read()
        {
            int i = c++;
            next();
            return i;
        }
        public int read(byte b[], int off, int len)
        {
            for (int i=0; i<len; i++)
              b[off+i] = (byte) (c++);
            next();
            return len;
        }

        // Move c to the next larger multiple of 10 if it is not
        // already on a multiple of 10.
        void next()
        {
            int remainder = c % 10;
            if (remainder != 0)
              c += (10-remainder);
        }
    }

    // This test makes sure the SkippingInputStream works.
    @Test public void test_SkippingInputStream()
    {
        SkippingInputStream is = new SkippingInputStream();
        byte b[] = new byte[16];
        int i = 0;
        b[i++] = (byte)is.read();
        b[i++] = (byte)is.read();
        b[i++] = (byte)is.read();
        is.read(b, i, 12);        i+= 12;
        b[i++] = (byte)is.read();

        byte expected[] = {10,
                           20,
                           30, 
                           40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
                           60};
        assertArrayEquals(expected, b);
    }


    // This verifies that the RefillingBufferedInputStream is
    // consuming block-sized chunks from the underlying stream,
    // even though it is returning data in variable-sized chunks.
    // It also exercises the 2 variants of read().
    @Test public void test_refilling()
        throws IOException
    {
        InputStream is =
          new RefillingBufferedInputStream(new SkippingInputStream(), 10);
        byte b[] = new byte[16];
        int i = 0;
        b[i++] = (byte)is.read();
        b[i++] = (byte)is.read();
        b[i++] = (byte)is.read();
        is.read(b, i, 12);        i+= 12;
        b[i++] = (byte)is.read();

        byte expected[] = {10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                           20, 21, 22, 23, 24, 25};
        assertArrayEquals(expected, b);
    }
}
