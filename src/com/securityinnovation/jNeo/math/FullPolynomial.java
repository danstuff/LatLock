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
 * This class provides an abstraction of a polynomial. Instances
 * contain an array of shorts that hold the polynomial coefficients
 * and the class provides operations to add, subtract, and multiply
 * polynomials together.
 */
public class FullPolynomial
{
    /**
     * The list of coefficients of the polynomial.
     */
    public short p[];


    /**
     * Initialize a polynomial with the given coefficient list.
     * The degree of the polynomial will be defined by the size of coeffs.
     *
     * @param coeffs the list of coefficients.
     */
    public FullPolynomial(
        short coeffs[])
    {
        p = coeffs;
    }


    /**
     * Initialize a polynomial of degree n whose coefficients are all 0.
     *
     * @param n the degree of the polynomial.
     */
    public FullPolynomial(
        int n)
    {
        p = new short[n];
        java.util.Arrays.fill(p, (short)0);
    }


    /**
     * Recenter the coefficients of a polynomial into the
     * range [newLowerLimit..newLowerLimit+q), such that
     * the new coefficients equal the old coefficients mod q.
     *
     * @param a the polynomial to be recentered.
     * @param q the coefficient modulus.
     * @param newLowerLimit the new smallest coefficient value.
     */
    public static final void recenterModQ(
        FullPolynomial a,
        int            q,
        int            newLowerLimit)
    {
        int newUpperLimit = newLowerLimit + q;
        for (int i=0; i<a.p.length; i++)
        {
            a.p[i] = (short) (a.p[i] % q);
            if (a.p[i] >= newUpperLimit)
              a.p[i] -= q;
            if (a.p[i] < newLowerLimit)
              a.p[i] += q;
        }
    }



    /**
     * Given two polynomials of the same degree N, compute a*b in
     * the ring of polynomials of degree N.
     *
     * @param a the first polynomial.
     * @param b the second polynomial. It must be of the same degree as a.
     *
     * @return a*b modulo X^N.
     */
    public static FullPolynomial convolution(
        FullPolynomial a,
        FullPolynomial b)
    {
        if (a.p.length != b.p.length)
          return new FullPolynomial(0);
        
        FullPolynomial c = new FullPolynomial(a.p.length);
        for (int i=0; i<a.p.length; i++)
          for (int j=0; j<b.p.length; j++)
            c.p[(i+j) % c.p.length] += (a.p[i] * b.p[j]);
        return c;
    }


    /**
     * Given two polynomials of the same degree N, compute a*b in
     * the ring of polynomials of degree N whose coefficients are
     * in the ring of integers mod coefficientModulus.
     *
     * @param a the first polynomial.
     * @param b the second polynomial. It must be of the same degree as a.
     * @param coefficientModulus the modulus for the coefficients of the
     *    resulting polynomial.
     *
     * @return a*b modulo X^N.
     */
    public static FullPolynomial convolution(
        FullPolynomial a,
        FullPolynomial b,
        int            coefficientModulus)
    {
        FullPolynomial c = convolution(a, b);
        recenterModQ(c, coefficientModulus, 0);
        return c;
    }


    /**
     * Add two polynomials modulo coefficientModulus.
     * The coefficients of the resulting polynomial will be
     * in the range [0..coefficientModulus-1].
     *
     * @param a the first addend.
     * @param b the second addend.
     * @param coefficientModulus the modulus for the polynomial coefficients
     *
     * @return the resulting polynomial.
     */
    public static final FullPolynomial add(
        FullPolynomial a,
        FullPolynomial b,
        int            coefficientModulus)
    {
        FullPolynomial c = new FullPolynomial(a.p.length);
        for (int i=0; i<c.p.length; i++)
          c.p[i] = (short) (a.p[i] + b.p[i]);
        recenterModQ(c, coefficientModulus, 0);
        return c;
    }


    /**
     * Add two polynomials modulo coefficientModulus.
     * The coefficients of the resulting polynomial will be
     * in the range [newLowerLimit..newLowerLimit+coefficientModulus-1].
     *
     * @param a the first addend.
     * @param b the second addend.
     * @param coefficientModulus the modulus for the polynomial coefficients.
     * @param newLowerLimit the smallest coefficient value of the result.
     *
     * @return the resulting polynomial.
     */
    public static final FullPolynomial addAndRecenter(
        FullPolynomial a,
        FullPolynomial b,
        int            coefficientModulus,
        int            newLowerLimit)
    {
        FullPolynomial c = new FullPolynomial(a.p.length);
        for (int i=0; i<c.p.length; i++)
          c.p[i] = (short) (a.p[i] + b.p[i]);
        recenterModQ(c, coefficientModulus, newLowerLimit);
        return c;
    }


    /**
     * Subtract two polynomials modulo coefficientModulus.
     * The coefficients of the resulting polynomial will be
     * in the range [0..coefficientModulus-1].
     *
     * @param a the minuend.
     * @param b the subtrahend.
     * @param coefficientModulus the modulus for the polynomial coefficients.
     *
     * @return the difference.
     */
    public static final FullPolynomial subtract(
        FullPolynomial a,
        FullPolynomial b,
        int            coefficientModulus)
    {
        FullPolynomial c = new FullPolynomial(a.p.length);
        for (int i=0; i<c.p.length; i++)
          c.p[i] = (short) (a.p[i] - b.p[i]);
        recenterModQ(c, coefficientModulus, 0);
        return c;
    }


    /**
     * Subtract two polynomials modulo coefficientModulus.
     * The coefficients of the resulting polynomial will be
     * in the range [0..coefficientModulus-1].
     *
     * @param a the minuend.
     * @param b the subtrahend.
     * @param coefficientModulus the modulus for the polynomial coefficients.
     * @param newLowerLimit the smallest coefficient value of the result.
     *
     * @return the difference.
     */
    public static final FullPolynomial subtractAndRecenter(
        FullPolynomial a,
        FullPolynomial b,
        int            coefficientModulus,
        int            newLowerLimit)
    {
        FullPolynomial c = new FullPolynomial(a.p.length);
        for (int i=0; i<c.p.length; i++)
          c.p[i] = (short) (a.p[i] - b.p[i]);
        recenterModQ(c, coefficientModulus, newLowerLimit);
        return c;
    }


    /**
     * Define polynomial equality based on the coefficient list.
     *
     * @param o the object to compare to.
     *
     * @return true iff o is a FullPolynomial with the same degree as
     *   this object and the respective coefficient lists contain the
     *   same values.
     */
    public boolean equals(
        Object o)
    {
        try {
            FullPolynomial other = (FullPolynomial) o;
            return java.util.Arrays.equals(p, other.p);
        } catch (Exception e) {}
        return false;
    }

    /**
     * Two polynomials have the same hash code if they are equal.
     */
    public int hashCode()
    {
        return java.util.Arrays.hashCode(p);
    }
}

