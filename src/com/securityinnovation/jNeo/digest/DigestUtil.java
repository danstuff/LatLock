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
 * <p>This class holds utility methods for manipulating
 * <code>Digest</code> objects. These methods are public to
 * the com.securityinnovation.jNeo.digest package.
 */
public class DigestUtil
{
    /**
     * Create an instance of the specified Hash subclass using the 
     * default constructor.
     */
    public static Digest create(
        Class clss)
    {
        // The newInstance can fail if clss is not a subclass of Digest
        // or the clss is missing the default constructor.
        try {return (Digest) clss.newInstance();}
        catch (Exception e) {return null;}
    }
}

