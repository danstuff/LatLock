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

package com.securityinnovation.jNeo.digest;


/**
 * This class provides an enumeration of hash algorithms that can
 * be used throughout the code. Each enumeration has a utility
 * function for creating a new instance of a Digest object
 * for that algorithm.
 */
public enum DigestAlgorithm
{
    /**
     * The enum for SHA1.
     */
    sha1(Sha1.class),

    /**
     * The enum for SHA256.
     */
    sha256(Sha256.class);



    /**
     * Constructor.
     */
    private DigestAlgorithm(
        Class _clss)
    {
        clss = _clss;
    }

    /**
     * The class used to generate objects
     */
    private Class clss;

    /**
     * Return the byte array identifying the OID.
     */
    public Digest newInstance()
    {
        try {return (Digest) clss.newInstance();}
        // By construction this shouldn't happen,
        // except perhaps an out-of-memory error.
        catch (Exception e) {return null;}
    }
};
