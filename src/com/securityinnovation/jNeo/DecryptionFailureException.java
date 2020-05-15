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
 * This exception indicates that a decryption operation failed. This
 * may be because the ciphertext has been corrupted or because the
 * wrong key was used. This exception is not used if the corrupt
 * ciphertext prevents the decryption calculation from even being
 * performed (for example, if the NtruEncrypt ciphertext is the wrong
 * length). It is used only if the decryption can proceed but fails
 * due to an internal error check, such as a CCM MAC verification
 * failure or an NtruEncrypt decryption candidate having the wrong
 * format.
 */
public class DecryptionFailureException extends NtruException
{
    /**
     * Constructs a new exception a default message.
     */
    public DecryptionFailureException()
    {
        super("Input ciphretext is not encrypted with this key");
    }
}
