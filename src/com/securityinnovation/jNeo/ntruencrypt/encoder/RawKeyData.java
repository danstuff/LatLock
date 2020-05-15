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
package com.securityinnovation.jNeo.ntruencrypt.encoder;

import com.securityinnovation.jNeo.math.FullPolynomial;
import com.securityinnovation.jNeo.ntruencrypt.KeyParams;

/**
 * This class holds the result of parsing a key blob. The
 * result contains the parameter set, the public key, and the
 * private key (which will be null if the input blob was a public
 * key blob).
 */
public class RawKeyData
{
    public KeyParams      keyParams;
    public FullPolynomial h;
    public FullPolynomial f;

    public RawKeyData(
        KeyParams      _keyParams,
        FullPolynomial _h)
    {
        keyParams = _keyParams;
        h = _h;
        f = null;
    }
    public RawKeyData(
        KeyParams      _keyParams,
        FullPolynomial _h,
        FullPolynomial _f)
    {
        keyParams = _keyParams;
        h = _h;
        f = _f;
    }
}


