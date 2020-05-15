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

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;


/**
 * This class implements the MGF-TP-1 algorithm for converting a byte
 * stream into a sequence of trits. It implements both the forward
 * direction (bytes -> trits as defined in X9.98) and the reverse
 * (trits -> bytes).
 */
public class MGF_TP_1
{
    /**
     * Generate a trinomial of degree N using the MGF-TP-1 algorithm
     * to convert the InputStream of bytes into trits.
     *
     * @param N   the degree of the new polynomial.
     * @param gen the byte sequence to be converted.
     *
     * @return the derived trinomial.
     */
    public static FullPolynomial genTrinomial(
        int          N,
        InputStream  gen)
    {
        try {
            FullPolynomial p = new FullPolynomial(N);

            int limit = 5 * (N / 5);
            int i = 0;
            while (i<limit)
            {
                int o = gen.read();
                if (o >= 243)
                  continue;
            
                int b;
                b = (o%3);  p.p[i++] = (byte)b;  o = (o-b)/3;
                b = (o%3);  p.p[i++] = (byte)b;  o = (o-b)/3;
                b = (o%3);  p.p[i++] = (byte)b;  o = (o-b)/3;
                b = (o%3);  p.p[i++] = (byte)b;  o = (o-b)/3;
                b = (o%3);  p.p[i++] = (byte)b;  o = (o-b)/3;
            }
            
            while (i<N)
            {
                int o = gen.read();
                if (o >= 243)
                  continue;
                
                int b;
                b = (o%3);  p.p[i++] = (byte)b;  o = (o-b)/3;  if (i==N) break;
                b = (o%3);  p.p[i++] = (byte)b;  o = (o-b)/3;  if (i==N) break;
                b = (o%3);  p.p[i++] = (byte)b;  o = (o-b)/3;  if (i==N) break;
                b = (o%3);  p.p[i++] = (byte)b;  o = (o-b)/3;  if (i==N) break;
                b = (o%3);  p.p[i++] = (byte)b;  o = (o-b)/3;  if (i==N) break;
            }
            
            // Renormalize from [0..2] to [-1..1]
            for (i=0; i<p.p.length; i++)
              if (p.p[i] == 2)
                p.p[i] = -1;
            
            return p;
        }
        catch (IOException e)
        {
            throw new InternalError("MGF-TP-1 byte source was unable to generate input");
        }
    }


    /**
     * Given a trit in the range [0..2], return a trit in
     * the range [-1..1] that is equal to the input mod 3.
     */
    private final static byte recenterTritTo0(
        short in)
    {
        if (in == -1)
          return 2;
        return (byte) (in);
    }


    /**
     * Generate a byte stream that is the encoding of a trinomial.
     * The byte stream will have the property that when it is run
     * through the MGF-TP-1 algorithm it will recover the original
     * trinomial.
     *
     * @param poly the trinomial. All coefficients must be in the range [0..2].
     * @param out  the output stream that will collect the input.
     */
    public static void encodeTrinomial(
        FullPolynomial poly,
        OutputStream   out)
    {
        try
        {
            int N = poly.p.length;
            int end, accum;
            // Encode 5 trits per byte, as long as we have >= 5 trits.
            for (end = 5; end <= N; end += 5)
            {
                accum = recenterTritTo0(poly.p[end-1]);
                accum = 3 * accum + recenterTritTo0(poly.p[end-2]);
                accum = 3 * accum + recenterTritTo0(poly.p[end-3]);
                accum = 3 * accum + recenterTritTo0(poly.p[end-4]);
                accum = 3 * accum + recenterTritTo0(poly.p[end-5]);
                out.write(accum);
            }

            // Encode the remaining trits.
            end = N - (N % 5);
            if (end < N)
            {
                accum = recenterTritTo0(poly.p[--N]);
                while (end < N)
                  accum = 3*accum + recenterTritTo0(poly.p[--N]);
                out.write(accum);
            }
        }
        catch (IOException e)
        {
            throw new InternalError("MGF-TP-1 byte sink was unable to process output");
        }
    }
}
