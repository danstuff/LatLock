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

import com.securityinnovation.jNeo.inputstream.IGF2;


/**
 * This class implements the BPGM3 algorithm defined in the X9.98 standard,
 * with a few modifications.
 *
 * <p> The main routine of this class requires that the IGF be initialized
 * before entry. This is to allow testing with known inputs.
 * 
 * <p>Also this implementation allows the number of "+1" coefficients
 * to be different from the number of "-1" coefficients. This was done
 * to support some experiments with the BPGM3.
 */
public class BPGM3
{
    /**
     * Generate a trinomial of degree N-1 that has <code>numOnes</code>
     * coeffcients set to +1 and <code>numNegOnes</code> coefficients
     * set to -1, and all other coefficients set to 0.
     */
    public static FullPolynomial genTrinomial(
        int          N,
        int          numOnes,
        int          numNegOnes,
        IGF2         igf)
    {
        boolean isSet[] = new boolean[N];
        for (int i=0; i<N; i++)
          isSet[i] = false;

        FullPolynomial p = new FullPolynomial(N);
        int t = 0;
        while (t < numOnes)
        {
            int i = igf.nextIndex();
            if (isSet[i])
              continue;

            p.p[i] = 1;
            isSet[i] = true;
            t++;
        }

        t = 0;
        while (t < numNegOnes)
        {
            int i = igf.nextIndex();
            if (isSet[i])
            {
                continue;
            }
            p.p[i] = -1;
            isSet[i] = true;
            t++;
        }

        return p;
    }
}
