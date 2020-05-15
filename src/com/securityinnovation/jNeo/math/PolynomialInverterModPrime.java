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
 * polynomial in the ring (Z/pZ)[X]/(X^N-1) for some prime p, as
 * defined in the NTRU Cryptosystems Technical Report #14 "Almost
 * Inverses and Fast NTRU Key Creation".
 *
 * <p>The prime modulus is supplied to the constructor, as a result each
 * instance of this class can compute inverses for one modulus.
 *
 * <p>This algorithm will not work if the modulus is not a prime number.
 */
public class PolynomialInverterModPrime implements PolynomialInverter
{
    /**
     * The modulus.
     */
    protected int prime;

    /**
     * A table of inverses mod <code>prime</code>. The table should be
     * set up so that 
     *    invModPrime[i] * i = 1 (mod prime) if the inverse of i exists
     *    invModPrime[i] = 0 if the inverse of i does not exist.
     */ 
    protected short invModPrime[];


    /**
     * This constructor initializes the object to calculate inverses
     * modulo a particular prime.
     *
     * @param _prime       the modulus.
     * @param _invModPrime a precomputed table of integer inverses modulo
     *    _prime. The table should be initialized so that
     *    invModPrime[i] * i = 1 (mod prime) if the inverse of i exists,
     *    invModPrime[i] = 0 if the inverse of i does not exist. This
     *    table should not be modified after it has been passed to the
     *    constructor.
     */ 
    public PolynomialInverterModPrime(
        int   _prime,
        short _invModPrime[])
    {
        prime = _prime;
        invModPrime = _invModPrime;
    }


    /**
     * Compute the inverse of a polynomial in (Z/pZ)[X]/(X^N-1)
     * See NTRU Cryptosystems Tech Report #014 "Almost Inverses
     * and Fast NTRU Key Creation."
     */
    public FullPolynomial invert(
        FullPolynomial a)
    {
        int N = a.p.length;

        // Initialization:
        // k=0, b(X) = 1, c(X) = 0, f(X)=a(X), g(X)=X^N-1
        int k = 0;
        FullPolynomial b = new FullPolynomial(N+1);
        FullPolynomial c = new FullPolynomial(N+1);
        FullPolynomial f = new FullPolynomial(N+1);
        FullPolynomial g = new FullPolynomial(N+1);
        b.p[0] = 1;
        for (int i=0; i<N; i++)
          f.p[i] = modPrime(a.p[i]);
        g.p[N] = 1;
        g.p[0] = (short) (prime-1);

        // Find the degree of f(X)
        int df = getDegree(f);

        // Find the degree of g(X). This is a constant based on initialization
        int dg = N;

        while (true)
        {
            // while f[0] = 0 {f/=X, c*=X, k++}
            while ((f.p[0] == 0) && (df > 0))
            {
                df--;
                divideByX(f);
                multiplyByX(c);
                k++;
            }

            if (df == 0)
            {
                // Make sure there is a solution.
                // Return null if a is not invertible
                int f0Inv = invModPrime[f.p[0]];
                if (f0Inv == 0)
                  return null;

                // b(X) = f[0]inv * b(X) mod p
                // return X^(N-k) * b
                int shift = N-k;
                shift %= N;
                if (shift < N) shift += N;
                FullPolynomial ret = new FullPolynomial(N);
                for (int i=0; i<N; i++)
                  ret.p[(i+shift) % N] = modPrime(f0Inv * b.p[i]);
                return ret;
            }

            if (df < dg)
            {
                // swap(f,g), swap(b,c);
                FullPolynomial tmpP;
                int            tmpD;
                tmpP=f;   f=g;   g=tmpP;
                tmpP=b;   b=c;   c=tmpP;
                tmpD=df; df=dg; dg=tmpD;
            }

            // u = f[0] * g[0]inv mod p
            int u = modPrime(f.p[0] * invModPrime[g.p[0]]);

            // f(X) -= u*g(X) mod p
            for (int i=0; i<f.p.length; i++)
              f.p[i] = modPrime(f.p[i] - u*g.p[i]);

            // b(X) -= u*c(X) mod p
            for (int i=0; i<b.p.length; i++)
              b.p[i] = modPrime(b.p[i] - u*c.p[i]);
        }
    }


    /**
     * Return the degree of a polynomial.
     */
    protected final static int getDegree(
        FullPolynomial f)
    {
        int df = f.p.length-1;
        while ((df > 0) && f.p[df] == 0)
          df--;
        return df;
    }

    /**
     * Returns x mod prime, always in the range [0..prime-1].
     * This differs from the % operator by returning a 
     * positive result when fed a negative number.
     */
    protected final short modPrime(int x)
    {
        x = x % prime;
        if (x < 0)
          x += prime;
        return (short) x;
    }

    /**
     * Divide f(X) by the polynomial g(X)=X. f(X) is updated in-place.
     * This effectively a "shift-left-with-wraparound" of the indices.
     */
    protected final static void divideByX(
        FullPolynomial f)
    {
        short f0 = f.p[0];
        for (int i=0; i<f.p.length-1; i++)
          f.p[i] = f.p[i+1];
        f.p[f.p.length-1] = f0;
    }

    /**
     * Mulitply f(X) by the polynomial g(X)=X. f(X) is updated in-place.
     * This effectively a "shift-right-with-wraparound" of the indices.
     */
    protected final static void multiplyByX(
        FullPolynomial f)
    {
        short fn = f.p[f.p.length-1];
        for (int i=f.p.length-1; i>0; i--)
          f.p[i] = f.p[i-1];
        f.p[0] = fn;
    }
}
