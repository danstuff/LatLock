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
 * This class implements the algorithm for finding the inverse of a
 * polynomial in the ring (Z/p^rZ)[X]/(X^N-1) for some prime p and
 * some exponent r, as defined in the NTRU Cryptosystems Technical
 * Report #14 "Almost Inverses and Fast NTRU Key Creation".
 *
 * <p>The prime p and the exponent r are supplied to the constructor,
 * as a result each instance of this class can compute inverses for
 * the modulus p^r.
 *
 * <p>This algorithm will not work if the modulus is not a power of
 * a prime number.
 */
public class PolynomialInverterModPowerOfPrime extends PolynomialInverterModPrime
{
    /**
     * The exponent the prime p must be raised to to compute the modulus.
     * That is, prime ^ powerOfPrime = modulus.
     */
    protected int powerOfPrime;

    
    /**
     * This constructor initializes the object to calculate inverses
     * modulo a particular prime.
     *
     * @param _powerOfPrime the exponent used to define the modulus.
     * @param _prime        the prime base of the modulus
     * @param _invModPrime a precomputed table of integer inverses modulo
     *    _prime. The table should be initialized so that
     *    invModPrime[i] * i = 1 (mod prime) if the inverse of i exists,
     *    invModPrime[i] = 0 if the inverse of i does not exist. This
     *    table should not be modified after it has been passed to the
     *    constructor.
     */ 
    public PolynomialInverterModPowerOfPrime(
        int   _powerOfPrime,
        int   _prime,
        short _invModPrime[])
    {
        super(_prime, _invModPrime);
        powerOfPrime = _powerOfPrime;
    }


    /**
     * Compute the inverse of a polynomial in (Z/p^rZ)[X]/(X^N-1)
     * See NTRU Cryptosystems Tech Report #014 "Almost Inverses
     * and Fast NTRU Key Creation."
     */
    public FullPolynomial invert(
        FullPolynomial a)
    {
        // b = a inverse mod prime
        FullPolynomial b = super.invert(a);

        // Make sure a was invertible
        if (b == null)
          return null;

        int q = prime;
        do
        {
            q *= q;

            // b(X) = b(X) * (2-a(X)b(X)) (mod q)
            //    i:   c = a*b
            FullPolynomial c = FullPolynomial.convolution(a, b, q);
            //    ii:  c = 2-a*b
            c.p[0] = (short) (2-c.p[0]);
            if (c.p[0] < 0)
              c.p[0] += (short) q;
            for (int i=1; i<b.p.length; i++)
              c.p[i] = (short) (q-c.p[i]); // This is -c (mod q)
            //    iii: b = b*(2-a*b) mod q
            if (q>powerOfPrime)
            	b = FullPolynomial.convolution(b, c, powerOfPrime);
            else
            	b = FullPolynomial.convolution(b, c, q);
        }while (q < powerOfPrime);
        
        return b;
    }
}
