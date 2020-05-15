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

import java.util.Arrays;

import org.junit.Test;
import static org.junit.Assert.*;


public class BitPackTestCase {

    @Test public void test_lowBitMask()
    {
        assertEquals(BitPack.lowBitMask(1),  0x01);
        assertEquals(BitPack.lowBitMask(2),  0x03);
        assertEquals(BitPack.lowBitMask(3),  0x07);
        assertEquals(BitPack.lowBitMask(4),  0x0f);
        assertEquals(BitPack.lowBitMask(5),  0x001f);
        assertEquals(BitPack.lowBitMask(6),  0x003f);
        assertEquals(BitPack.lowBitMask(7),  0x007f);
        assertEquals(BitPack.lowBitMask(8),  0x00ff);
        assertEquals(BitPack.lowBitMask(9),  0x01ff);
        assertEquals(BitPack.lowBitMask(10), 0x03ff);
        assertEquals(BitPack.lowBitMask(11), 0x07ff);
        assertEquals(BitPack.lowBitMask(12), 0x0fff);
        assertEquals(BitPack.lowBitMask(13), 0x1fff);
        assertEquals(BitPack.lowBitMask(14), 0x3fff);
        assertEquals(BitPack.lowBitMask(15), 0x7fff);
        assertEquals(BitPack.lowBitMask(16), 0xffff);
    }

    @Test public void test_pack_getLength()
    {
        assertEquals(12,          BitPack.pack(12, 0x100, null, 0, null, 0));
        assertEquals((12*9+7)/8,  BitPack.pack(12, 0x200, null, 0, null, 0));
        assertEquals((14*10+7)/8, BitPack.pack(14, 0x400, null, 0, null, 0));
        assertEquals((21*11+7)/8, BitPack.pack(21, 0x800, null, 0, null, 0));
        assertEquals((13*12+7)/8, BitPack.pack(13, 0x1000, null, 0, null, 0));
        assertEquals((19*13+7)/8, BitPack.pack(19, 0x2000, null, 0, null, 0));
        assertEquals((19*14+7)/8, BitPack.pack(19, 0x4000, null, 0, null, 0));
        assertEquals((19*15+7)/8, BitPack.pack(19, 0x8000, null, 0, null, 0));
        assertEquals((19*16+7)/8, BitPack.pack(19, 0x10000, null, 0, null, 0));
    }


    @Test public void test_pack5()
    {
        short src[]   = {0x10, 0x01, 0x11, 0x1f, 0x00, 0x12, 0x1a, 0x1c, 0x01};
        byte exptgt[] = {(byte)0x80, (byte)0x63, (byte)0xf0, (byte)0x4b,
                         (byte)0x5c, (byte) 0x08};
        byte  tgt[] = new byte[exptgt.length];
        
        assertEquals(tgt.length,
                     BitPack.pack(src.length, 0x20, src, 0, tgt, 0));
        assertTrue(Arrays.equals(exptgt, tgt));
    }

    @Test public void test_pack8()
    {
        short src[]   = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88};
        byte exptgt[] = {(byte)0x80, (byte)0x81, (byte)0x82, (byte)0x83,
                         (byte)0x84, (byte)0x85, (byte)0x86, (byte)0x87,
                         (byte)0x88};
        byte  tgt[] = new byte[exptgt.length];
        
        assertEquals(tgt.length,
                     BitPack.pack(src.length, 0x100, src, 0, tgt, 0));
        assertTrue(Arrays.equals(exptgt, tgt));
    }

    @Test public void test_pack9()
    {
        short src[] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88};
        byte exptgt[] = {(byte)0x40, (byte)0x20, (byte)0x50, (byte)0x48,
                         (byte)0x34, (byte)0x22, (byte)0x15, (byte)0x0c,
                         (byte)0x87, (byte)0x44, (byte)0x00};
        byte  tgt[] = new byte[exptgt.length];
        
        assertEquals(tgt.length,
                     BitPack.pack(src.length, 0x200, src, 0, tgt, 0));
        assertTrue(Arrays.equals(exptgt, tgt));
    }


    @Test public void test_pack10()
    {
        short src[] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88};
        byte exptgt[] = {(byte)0x20, (byte)0x08, (byte)0x12, (byte)0x08,
                         (byte)0x83, (byte)0x21, (byte)0x08, (byte)0x52,
                         (byte)0x18, (byte)0x87, (byte)0x22, (byte)0x00};
        byte  tgt[] = new byte[exptgt.length];
        
        assertEquals(tgt.length,
                     BitPack.pack(src.length, 0x400, src, 0, tgt, 0));
        assertTrue(Arrays.equals(exptgt, tgt));
    }

    @Test public void test_pack11()
    {
        short src[] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88};
        byte exptgt[] = {(byte)0x10, (byte)0x02, (byte)0x04, (byte)0x41,
                         (byte)0x08, (byte)0x31, (byte)0x08, (byte)0x21,
                         (byte)0x44, (byte)0x30, (byte)0x87, (byte)0x11,
                         (byte)0x00};
        byte  tgt[] = new byte[exptgt.length];
        
        assertEquals(tgt.length,
                     BitPack.pack(src.length, 0x800, src, 0, tgt, 0));
        assertTrue(Arrays.equals(exptgt, tgt));
    }

    @Test public void test_pack12()
    {
        short src[] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88};
        byte exptgt[] = {(byte)0x08, (byte)0x00, (byte)0x81, (byte)0x08,
                         (byte)0x20, (byte)0x83, (byte)0x08, (byte)0x40,
                         (byte)0x85, (byte)0x08, (byte)0x60, (byte)0x87,
                         (byte)0x08, (byte)0x80};
        byte  tgt[] = new byte[exptgt.length];
        
        assertEquals(tgt.length,
                     BitPack.pack(src.length, 0x1000, src, 0, tgt, 0));
        assertTrue(Arrays.equals(exptgt, tgt));
    }



    public byte [] maskToBytes(
        short s[])
    {
        byte b[] = new byte[s.length];
        for (int i=0; i<s.length; i++)
          b[i] = (byte) (s[i]);
        return b;
    }
    
    @Test public void test_unpack5()
    {
        byte  src[] = {(byte)0x80, (byte)0x63, (byte)0xf0, (byte)0x4b,
                       (byte)0x5c, (byte) 0x08};
        short exptgt[]= {0x10, 0x01, 0x11, 0x1f, 0x00, 0x12, 0x1a, 0x1c, 0x01};
        short tgt[] = new short[exptgt.length];
        
        assertEquals(src.length,
                     BitPack.unpack(tgt.length, 0x20, src, 0, tgt, 0));
        assertTrue(Arrays.equals(exptgt, tgt));
    }

    @Test public void test_unpack8()
    {
        byte  src[] = {(byte)0x80, (byte)0x81, (byte)0x82, (byte)0x83,
                       (byte)0x84, (byte)0x85, (byte)0x86, (byte)0x87,
                       (byte)0x88};
        short exptgt[]= {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88};
        short tgt[] = new short[exptgt.length];
        
        assertEquals(src.length,
                     BitPack.unpack(tgt.length, 0x100, src, 0, tgt, 0));
        assertTrue(Arrays.equals(exptgt, tgt));
    }

    @Test public void test_unpack9()
    {
        byte  src[] = {(byte)0x40, (byte)0x20, (byte)0x50, (byte)0x48,
                       (byte)0x34, (byte)0x22, (byte)0x15, (byte)0x0c,
                       (byte)0x87, (byte)0x44, (byte)0x00};
        short exptgt[]= {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88};
        short tgt[] = new short[exptgt.length];
        
        assertEquals(src.length,
                     BitPack.unpack(tgt.length, 0x200, src, 0, tgt, 0));
        assertTrue(Arrays.equals(exptgt, tgt));
    }


    @Test public void test_unpack10()
    {
        byte  src[] = {(byte)0x20, (byte)0x08, (byte)0x12, (byte)0x08,
                       (byte)0x83, (byte)0x21, (byte)0x08, (byte)0x52,
                       (byte)0x18, (byte)0x87, (byte)0x22, (byte)0x00};
        short exptgt[]= {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88};
        short tgt[] = new short[exptgt.length];
        
        assertEquals(src.length,
                     BitPack.unpack(tgt.length, 0x400, src, 0, tgt, 0));
        assertTrue(Arrays.equals(exptgt, tgt));
    }

    @Test public void test_unpack11()
    {
        byte  src[] = {(byte)0x10, (byte)0x02, (byte)0x04, (byte)0x41,
                       (byte)0x08, (byte)0x31, (byte)0x08, (byte)0x21,
                       (byte)0x44, (byte)0x30, (byte)0x87, (byte)0x11,
                       (byte)0x00};
        short exptgt[]= {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88};
        short tgt[] = new short[exptgt.length];
        
        assertEquals(src.length,
                     BitPack.unpack(tgt.length, 0x800, src, 0, tgt, 0));
        assertTrue(Arrays.equals(exptgt, tgt));
    }

    @Test public void test_unpack12()
    {
        byte src[] = {(byte)0x08, (byte)0x00, (byte)0x81, (byte)0x08,
                      (byte)0x20, (byte)0x83, (byte)0x08, (byte)0x40,
                      (byte)0x85, (byte)0x08, (byte)0x60, (byte)0x87,
                      (byte)0x08, (byte)0x80};
        short exptgt[]= {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88};
        short tgt[] = new short[exptgt.length];
        
        assertEquals(src.length,
                     BitPack.unpack(tgt.length, 0x1000, src, 0, tgt, 0));
        assertTrue(Arrays.equals(exptgt, tgt));
    }


    @Test public void test_pack9_limited()
    {
        short src[] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88};
        byte  exptgt[] = {0x40, 0x20, 0x50};
        byte  tgt[] = new byte[exptgt.length];
        
        assertEquals(tgt.length,
                     BitPack.pack(src.length, 0x200, 3, src, 0, tgt, 0));
        assertTrue(Arrays.equals(exptgt, tgt));
    }


    @Test public void test_pack12_limited()
    {
        short src[] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88};
        byte  exptgt[] = {(byte)0x08, (byte)0x00, (byte)0x81,
                          (byte)0x08, (byte)0x20, (byte)0x83};
        byte  tgt[] = new byte[exptgt.length];
        
        assertEquals(tgt.length,
                     BitPack.pack(src.length, 0x1000, 6, src, 0, tgt, 0));
        assertTrue(Arrays.equals(exptgt, tgt));
    }

    private byte[] subArray(
        byte a[],
        int  fromIndex,
        int  toIndex)
    {
        int len = toIndex-fromIndex+1;
        if (len < 0)
          return new byte[0];

        byte b[] = new byte[len];
        System.arraycopy(a, fromIndex, b, 0, len);
        return b;
    }


    @Test public void test_pack12_long()
    {
        short src[] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88};
        byte exptgt[] = {(byte)0x08, (byte)0x00, (byte)0x81, (byte)0x08,
                         (byte)0x20, (byte)0x83, (byte)0x08, (byte)0x40,
                         (byte)0x85, (byte)0x08, (byte)0x60, (byte)0x87,
                         (byte)0x08, (byte)0x80};
        byte  tgt[] = new byte[exptgt.length+10];

        // Ask for more output bytes that are possible to generate
        assertEquals(exptgt.length,
                     BitPack.pack(src.length, 0x1000, tgt.length,
                                  src, 0, tgt, 0));
        // Verify the output
        assertTrue(Arrays.equals(exptgt, subArray(tgt, 0, exptgt.length-1)));
    }
}
