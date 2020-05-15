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

import com.securityinnovation.jNeo.ParamSetNotSupportedException;
import com.securityinnovation.jNeo.math.BitPack;
import com.securityinnovation.jNeo.math.FullPolynomial;
import com.securityinnovation.jNeo.ntruencrypt.KeyParams;


class PubKeyFormatter_PUBLIC_KEY_v1 implements PubKeyFormatter
{
    private final static byte tag = NtruEncryptKeyNativeEncoder.PUBLIC_KEY_v1;

    public byte[] encode(
        KeyParams      keyParams,
        FullPolynomial h)
    {
        if (h.p.length != keyParams.N)
          return null;

        int len = (KeyFormatterUtil.fillHeader(tag, keyParams.OIDBytes, null) +
                   BitPack.pack(keyParams.N, keyParams.q));
        byte ret[] = new byte[len];

        int offset = KeyFormatterUtil.fillHeader(tag, keyParams.OIDBytes, ret);
        BitPack.pack(keyParams.N, keyParams.q, h.p, 0, ret, offset);
        return ret;
    }

    public RawKeyData decode(
        byte keyBlob[])
        throws ParamSetNotSupportedException
    {
        // Parse the header, recover the key parameters.
        if (keyBlob[0] != tag)
          throw new IllegalArgumentException("key blob tag not recognized");
        KeyParams keyParams = KeyFormatterUtil.parseOID(keyBlob, 1, 3);

        // Make sure the input will be fully consumed
        int headerLen = KeyFormatterUtil.getHeaderEndOffset(keyBlob);
        int packedHLen = BitPack.unpack(keyParams.N, keyParams.q);
        if (headerLen + packedHLen != keyBlob.length)
          throw new IllegalArgumentException(
              "Input public key blob is " + keyBlob.length + " bytes, not " +
              "the expected " + (headerLen + packedHLen));

        // Recover h
        FullPolynomial h = new FullPolynomial(keyParams.N);
        BitPack.unpack(keyParams.N, keyParams.q, keyBlob, headerLen, h.p, 0);

        // Return the key material
        return new RawKeyData(keyParams, h);
    }
}
