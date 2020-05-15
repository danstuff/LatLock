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

import java.io.ByteArrayInputStream;


public class IGF2TestCase {

    // Create a new IGF using bitsPerElement and inputStream. Use it
    // to generate expectedOutputStream.length indices.
    // Verify the output matches the expected value.
    private boolean checkIGF(
        int   bitsPerElement,
        byte  inputStream[],
        short expectedOutputStream[])
    {
        ByteArrayInputStream input = new ByteArrayInputStream(inputStream);
        short out[] = new short[expectedOutputStream.length];
        IGF2 igf = new IGF2((1<<bitsPerElement), bitsPerElement, input);
        for (int i=0; i<out.length; i++)
          out[i] = (short) igf.nextIndex();
        return java.util.Arrays.equals(out, expectedOutputStream);        
    }


    // Perform a known-vector test reading 8 bits at a time.
    @Test public void test_8bit()
    {
        byte src[] = {(byte)0x80, (byte)0x81, (byte)0x82, (byte)0x83, 
                      (byte)0x84, (byte)0x85, (byte)0x86, (byte)0x87,
                      (byte)0x88};
        short expected[] = {0x80, 0x81, 0x82, 0x83, 0x84,
                            0x85, 0x86, 0x87, 0x88};

        assertTrue(checkIGF(8, src, expected));
    }

    // Perform a known-vector test reading 9 bits at a time.
    @Test public void test_9bit()
    {
        byte src[] = {(byte)0x40, (byte)0x20, (byte)0x50, (byte)0x48, 
                      (byte)0x34, (byte)0x22, (byte)0x15, (byte)0x0c,
                      (byte)0x87, (byte)0x44, (byte)0x00};
        short expected[] = {0x80, 0x81, 0x82, 0x83, 0x84,
                            0x85, 0x86, 0x87, 0x88};
        assertTrue(checkIGF(9, src, expected));
    }

    // Perform a known-vector test reading 10 bits at a time.
    @Test public void test_10bit()
    {
        byte src[] = {(byte)0x20, (byte)0x08, (byte)0x12, (byte)0x08,
                      (byte)0x83, (byte)0x21, (byte)0x08, (byte)0x52,
                      (byte)0x18, (byte)0x87, (byte)0x22, (byte)0x00};
        short expected[] = {0x80, 0x81, 0x82, 0x83, 0x84,
                            0x85, 0x86, 0x87, 0x88};
        assertTrue(checkIGF(10, src, expected));
    }

    // Perform a known-vector test reading 11 bits at a time.
    @Test public void test_11bit()
    {
        byte src[] = {(byte)0x10, (byte)0x02, (byte)0x04, (byte)0x41,
                      (byte)0x08, (byte)0x31, (byte)0x08, (byte)0x21,
                      (byte)0x44, (byte)0x30, (byte)0x87, (byte)0x11,
                      (byte)0x00};
        short expected[] = {0x80, 0x81, 0x82, 0x83, 0x84,
                            0x85, 0x86, 0x87, 0x88};
        assertTrue(checkIGF(11, src, expected));
    }

    // Perform a known-vector test reading 12 bits at a time.
    @Test public void test_12bit()
    {
        byte src[] = {(byte)0x08, (byte)0x00, (byte)0x81, (byte)0x08,
                      (byte)0x20, (byte)0x83, (byte)0x08, (byte)0x40,
                      (byte)0x85, (byte)0x08, (byte)0x60, (byte)0x87,
                      (byte)0x08, (byte)0x80};
        short expected[] = {0x80, 0x81, 0x82, 0x83, 0x84,
                            0x85, 0x86, 0x87, 0x88};
        assertTrue(checkIGF(12, src, expected));
    }
}
