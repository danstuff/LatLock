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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import com.securityinnovation.jNeo.ParamSetNotSupportedException;
import com.securityinnovation.jNeo.math.BitPack;
import com.securityinnovation.jNeo.math.FullPolynomial;
import com.securityinnovation.jNeo.math.MGF_TP_1;
import com.securityinnovation.jNeo.ntruencrypt.KeyParams;


class PrivKeyFormatter_PrivateKeyPackedFv1 implements PrivKeyFormatter
{
    private final static byte tag = NtruEncryptKeyNativeEncoder.PRIVATE_KEY_DEFAULT_v1;

    public byte[] encode(
        KeyParams      keyParams,
        FullPolynomial h,
        FullPolynomial f)
    {
        // Sanity-check inputs
        if ((h.p.length != keyParams.N) || (f.p.length != keyParams.N))
          throw new IllegalArgumentException("exported key invalid");

        // Convert f to a packed F.
        FullPolynomial F = KeyFormatterUtil.recoverF(f);
        ByteArrayOutputStream os = new ByteArrayOutputStream((f.p.length+4)/5);
        MGF_TP_1.encodeTrinomial(F, os);
        byte encodedF[] = os.toByteArray();

        // Allocate output buffer
        int len = (KeyFormatterUtil.fillHeader(tag, keyParams.OIDBytes, null) +
                   BitPack.pack(keyParams.N, keyParams.q) +
                   encodedF.length);
        byte ret[] = new byte[len];

        // Encode the output
        int offset = KeyFormatterUtil.fillHeader(tag, keyParams.OIDBytes, ret);
        offset += BitPack.pack(keyParams.N, keyParams.q, h.p, 0, ret, offset);
        System.arraycopy(encodedF, 0, ret, offset, encodedF.length);
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
        int packedFLen = (keyParams.N + 4) / 5;
        if (headerLen + packedHLen + packedFLen != keyBlob.length)
          throw new IllegalArgumentException("key blob length invalid");

        // Recover h
        int offset = headerLen;
        FullPolynomial h = new FullPolynomial(keyParams.N);
        offset += BitPack.unpack(
            keyParams.N, keyParams.q, keyBlob, offset, h.p, 0);

        // Recover F
        ByteArrayInputStream is = 
          new ByteArrayInputStream(keyBlob, offset, keyBlob.length-offset);
        FullPolynomial f = MGF_TP_1.genTrinomial(keyParams.N, is);

        // Compute f = 1+p*F
        for (int i=0; i<f.p.length; i++)
          f.p[i] *= keyParams.p;
        f.p[0]++;

        
        // Return the key material
        return new RawKeyData(keyParams, h, f);
    }
}
