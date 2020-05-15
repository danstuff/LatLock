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
 * This exception indicates that the header tag of an input key blob 
 * is not recognized.
 */
public class FormatNotSupportedException extends NtruException
{
    /**
     * Constructs a new exception with the supplied key blob tag as
     * the detail message.
     */
    public FormatNotSupportedException(
        byte tag)
    {
        super("Blob format (" + Integer.toHexString(0xff&tag) + 
              ") is not supported");
    }
}
