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
package com.securityinnovation.jNeo;

/**
 * This exception indicates that the input key blob contains a key that
 * uses an NtruEncrypt or NtruSign parameter set that is not supported
 * by this implementation.
 */
public class ParamSetNotSupportedException extends NtruException
{
    /**
     * Constructs a new exception with the supplied OID as the detail message,
     * formatted as "w.x.y.z".
     */
    public ParamSetNotSupportedException(
        byte oid[])
    {
        super("Ntru key parameter set (" + oidToString(oid) +
              ") is not supported");
    }


    /**
     * Constructs a new exception with the supplied OID's name as
     * the detail message.
     */
    public ParamSetNotSupportedException(
        OID oid)
    {
        super("Ntru key parameter set (" + oid + ") is not supported");
    }


    /**
     * Create a string containing the OID as "w.x.y.z".
     */
    private static String oidToString(
        byte oid[])
    {
        String s = "";
        if (oid.length > 0)
          s += oid[0];
        for (int i=1; i<oid.length; i++)
          s += "." + (0xff & oid[i]);
        return s;
    }
}
