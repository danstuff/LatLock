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

package com.securityinnovation.testvectors;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;

import com.securityinnovation.jNeo.OID;
import com.securityinnovation.jNeo.OIDMap;
import com.securityinnovation.jNeo.NtruException;
import com.securityinnovation.jNeo.Random;
import com.securityinnovation.jNeo.digest.Sha256;
import com.securityinnovation.jNeo.ntruencrypt.NtruEncryptKey;
//import com.securityinnovation.testvectors.;

public class NtruEncryptTestVectorGenerator
{
    private static byte[] makeSeed(
        OID    oid,
        String usage)
        throws IOException
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bos);
        out.writeBytes(oid.toString());
        out.writeBytes(" ");
        out.writeBytes(usage);
        out.close();
        byte b[] = bos.toByteArray();
        bos.close();

        // hash it
        Sha256 s = new Sha256();
        byte b2[] = new byte[s.getDigestLen()];
        s.digest(b, 0, b.length, b2, 0);
        return b2;
    }

    public static byte m[] = {0x41, 0x42, 0x43};

    public static void main(String args[])
        throws NtruException, IOException
    {
        for (OID oid : OID.values())
        {
            //TVDump.setOID(oid);
            byte oidBytes[] = OIDMap.getOIDBytes(oid);
            System.out.println("    // OID = " + oid + "  " +
                               oidBytes[0] + "." +
                               oidBytes[1] + "." +
                               oidBytes[2]);

            byte seed[] = makeSeed(oid, "keygen");
            //TVDump.dumpHex("keygenSeed", seed);
            Random r = new Random(seed);
            NtruEncryptKey key = NtruEncryptKey.genKey(oid, r);

            seed = makeSeed(oid, "encrypt");
            //TVDump.dumpHex("encryptSeed", seed);
            r.seed(seed);
            byte ct[] = key.encrypt(m, r);
            key.decrypt(ct);

            System.out.println("\n\n");
        }
    }
}
