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
package com.securityinnovation.jNeo.ntruencrypt;

import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import com.securityinnovation.jNeo.OID;
import com.securityinnovation.jNeo.Random;
import com.securityinnovation.jNeo.RandomExtractor;
import com.securityinnovation.jNeo.NtruException;
import com.securityinnovation.jNeo.CiphertextBadLengthException;
import com.securityinnovation.jNeo.DecryptionFailureException;
import com.securityinnovation.jNeo.FormatNotSupportedException;
import com.securityinnovation.jNeo.PlaintextBadLengthException;
import com.securityinnovation.jNeo.NoPrivateKeyException;
import com.securityinnovation.jNeo.ObjectClosedException;
import com.securityinnovation.jNeo.ParamSetNotSupportedException;
import com.securityinnovation.jNeo.math.FullPolynomial;
import com.securityinnovation.jNeo.math.MGF_TP_1;
import com.securityinnovation.jNeo.math.BPGM3;
import com.securityinnovation.jNeo.math.BitPack;
import com.securityinnovation.jNeo.inputstream.MGF1;
import com.securityinnovation.jNeo.inputstream.IGF2;
import com.securityinnovation.jNeo.ntruencrypt.encoder.NtruEncryptKeyNativeEncoder;
import com.securityinnovation.jNeo.ntruencrypt.encoder.RawKeyData;
import com.securityinnovation.jNeo.ntruencrypt.encoder.KeyFormatterUtil;


/**
 * This class represents NtruEncrypt keys. An instance may hold
 * a public/private keypair or just the public key.
 */
public class NtruEncryptKey
{
    /**
     * The parameter set for this key.
     */
    protected KeyParams      keyParams = null;


    /**
     * The public key.
     */
    protected FullPolynomial h = null;


    /**
     * The private key f (= 1+p*F). For public-key-only objects this
     * will be null.
     */
    protected FullPolynomial f = null;


    /**
     * Generate a new keypair for the specified parameter set.
     * (see com.securityinnovation.jNeo.OID for a list of parameter set identifiers).
     */
    public static NtruEncryptKey genKey(
        OID          oid,
        Random       prng)
        throws ParamSetNotSupportedException
    {
        if (oid == null)
          throw new NullPointerException("oid is null");
        if (prng == null)
          throw new NullPointerException("prng is null");
        return genKey(oid, RandomExtractor.extractRNG(prng));
    }


    /**
     * Generate a new keypair for the specified parameter set
     * using the supplied InputStream as a source of randomness.
     */
    static NtruEncryptKey genKey(
        OID          oid,
        InputStream  prng)
        throws ParamSetNotSupportedException
    {
        KeyParams keyParams = KeyParams.getKeyParams(oid);

        IGF2 igf = new IGF2(keyParams.N, keyParams.c, prng);

        // Generate trinomial g that is invertible
        FullPolynomial g = null;
        boolean gIsInvertible = false;
        while (!gIsInvertible)
        {
            g = BPGM3.genTrinomial(
                keyParams.N, keyParams.dg+1, keyParams.dg, igf);
            FullPolynomial gInv = keyParams.polyInverter.invert(g);
            gIsInvertible = (gInv != null);
        }

        // Create F, f=1+p*F, and f^-1 mod q
        FullPolynomial F = null, f = null, fInv = null;
        boolean fIsInvertible = false;
        while (!fIsInvertible)
        {
            // Generate random F
            F = BPGM3.genTrinomial(
                keyParams.N, keyParams.df, keyParams.df, igf);
            
            // Calculate f = 1+p*f
            f = new FullPolynomial(keyParams.N);
            for (int i=0; i<keyParams.N; i++)
              f.p[i] = (short) (keyParams.p*F.p[i]);
            f.p[0]++;

            // Compute f^-1 mod q. Check whether the operation succeeded.
            fInv = keyParams.polyInverter.invert(f);
            fIsInvertible = (fInv != null);
        }

        // Calculate h = f^-1 * g * p mod q
        FullPolynomial h = FullPolynomial.convolution(fInv, g);
        for (int i=0; i<h.p.length; i++)
        {
            h.p[i] = (short) ((h.p[i] * keyParams.p) % keyParams.q);
            if (h.p[i] < 0)
              h.p[i] += keyParams.q;
        }

        return new NtruEncryptKey(keyParams, h, f);
    }


    /**
     * Initialize the NtruEncryptKey with the key parameters.
     */
    NtruEncryptKey(
        KeyParams      _keyParams,
        FullPolynomial _h,
        FullPolynomial _f)
    {
        keyParams = _keyParams;
        h = _h;
        f = _f;
    }


    /**
     * Create a new key from the supplied keyblob. The key blob
     * can be either a public or private key blob generated with
     * <code>getPubKey()</code> or <code>getPrivKey()</code>.
     */
    public NtruEncryptKey(
        byte keyBlob[])
        throws FormatNotSupportedException, ParamSetNotSupportedException
    {
        NtruEncryptKeyNativeEncoder encoder = new NtruEncryptKeyNativeEncoder();
        RawKeyData rawKey = encoder.decodeKeyBlob(keyBlob);
        keyParams = rawKey.keyParams;
        h = rawKey.h;
        f = rawKey.f;
    }

    /**
     * Create an empty key object associated with the supplied parameter
     * set. This is for use in unit testing where the key material is
     * not used.
     */
    NtruEncryptKey(
        OID oid)
        throws ParamSetNotSupportedException
    {
        keyParams = KeyParams.getKeyParams(oid);
    }


    /**
     * Signal that this app is finished using this key. This clears
     * all sensitive memory stored by the object and makes the object
     * unusable.
     */
    public void close()
    {
        if (h != null)
          java.util.Arrays.fill(h.p, (byte)0);
        h = null;
        if (f != null)
          java.util.Arrays.fill(f.p, (byte)0);
        f = null;
    }

    /**
     * Return the blob of the public key.
     */
    public byte[] getPubKey()
        throws ObjectClosedException
    {
        if (h == null)
          throw new ObjectClosedException();
        NtruEncryptKeyNativeEncoder encoder = new NtruEncryptKeyNativeEncoder();
        return encoder.encodePubKey(keyParams, h);
    }

    /**
     * Return the blob of the private key.
     */
    public byte[] getPrivKey()
        throws ObjectClosedException, NoPrivateKeyException
    {
        if (h == null)
          throw new ObjectClosedException();
        if (f == null)
          throw new NoPrivateKeyException();

        NtruEncryptKeyNativeEncoder encoder = new NtruEncryptKeyNativeEncoder();
        return encoder.encodePrivKey(keyParams, h, f);
    }


    /**
     * Encrypt message and return the ciphertext.
     *
     * @param message the plaintext
     * @param prng the PRNG to use as a source of randomness during encryption.
     */
    public byte[] encrypt(
        byte    message[],
        Random  prng)
        throws ObjectClosedException, PlaintextBadLengthException
    {
        if (prng == null)
          throw new NullPointerException("NtruEncrypt input PRNG is NULL");
        return encrypt(message, RandomExtractor.extractRNG(prng));
    }


    /* encrypt
     *
     * Encrypt message into ciphertext using the supplied inputstream
     * as a source of randomness.
     */
    protected byte[] encrypt(
        byte         message[],
        InputStream  rng)
        throws ObjectClosedException, PlaintextBadLengthException
    {
        if (h == null)
          throw new ObjectClosedException();
        // Sanity check input
        if (message == null)
          throw new NullPointerException("NtruEncrypt input plaintext is NULL");

        // Check input length
        if (keyParams.maxMsgLenBytes < message.length)
          throw new PlaintextBadLengthException(
              message.length, keyParams.maxMsgLenBytes);

        FullPolynomial mPrime, R;
        do {
            // Form M = b | len | message | p0
            byte M[] = generateM(message, rng);
            
            // Form Mtrin = trinary poly derived from M
            FullPolynomial Mtrin = new FullPolynomial(
                convPolyBinaryToTrinary(keyParams.N, M));
            
            // Form sData = OID | m | b | hTrunc
            byte sData[] = form_sData(message, 0, message.length, M, 0);
            
            // Form r from sData.
            IGF2 igf = new IGF2(
                keyParams.N, keyParams.c, keyParams.igfHash, keyParams.minCallsR, 
                sData, 0, sData.length);
            FullPolynomial r = BPGM3.genTrinomial(
                keyParams.N, keyParams.dr, keyParams.dr, igf);
            igf.close();
            
            // Calculate R = r * h mod q
            R = FullPolynomial.convolution(r, h, keyParams.q);
            
            // calculate R4 = R mod 4, form octet string
            // calc mask = MGF1(R4, N, minCallsMask)
            FullPolynomial mask = calcEncryptionMask(R);
            
            // calc m' = M + mask mod p
            mPrime = 
              FullPolynomial.addAndRecenter(Mtrin, mask, keyParams.p, -1);

            // count #1s, #0s, #-1s in m', discard if less than dm0
        } while (!check_dm0(mPrime, keyParams.dm0));

        // e = R + m' mod q
        FullPolynomial e = FullPolynomial.add(R, mPrime, keyParams.q);

        // Bit-pack e into the ciphertext and return.
        int cLen = BitPack.pack(e.p.length, keyParams.q);
        byte ciphertext[] = new byte[cLen];
        BitPack.pack(e.p.length, keyParams.q, e.p, 0, ciphertext, 0);
        return ciphertext;
    }


    /**
     * Decrypt a ciphertext and return the plaintext. On error an 
     * exception is thrown.
     *
     * @param ciphertext the input ciphertext.
     *
     * @return the decrypted plaintext.
     */
    public byte[] decrypt(
        byte ciphertext[])
        throws NoPrivateKeyException, CiphertextBadLengthException,
               ObjectClosedException, DecryptionFailureException
    {
        if (ciphertext == null)
          throw new NullPointerException("NtruDecrypt input ciphertext is NULL");
        if (h == null)
          throw new ObjectClosedException();
        if (f == null)
          throw new NoPrivateKeyException();
        int expectedCTLength = BitPack.pack(keyParams.N, keyParams.q);
        if (ciphertext.length != expectedCTLength)
          throw new CiphertextBadLengthException(
              ciphertext.length, expectedCTLength);

        boolean fail = false;

        // Unpack ciphertext into the polynomial e.
        FullPolynomial e = new FullPolynomial(keyParams.N);
        int numUnpacked = BitPack.unpack(
            keyParams.N, keyParams.q, ciphertext, 0, e.p, 0);
        if (numUnpacked != ciphertext.length)
          throw new CiphertextBadLengthException(
              ciphertext.length, BitPack.pack(keyParams.N, keyParams.q));

        // a = f*e with coefficients reduced to range [A..A+q-1], where
        // A = lower bound decryption coefficient (-q/2 in all param sets)
        FullPolynomial ci = FullPolynomial.convolution(f, e, keyParams.q);
        for (int i=0; i<ci.p.length; i++)
          if (ci.p[i] >= keyParams.q/2)
            ci.p[i] -= keyParams.q;
        
        // Calculate ci = message candidate = a mod p in [-1,0,1]
        for (int i=0; i<keyParams.N; i++)
        {
            ci.p[i] = (byte) (ci.p[i] % keyParams.p);
            if (ci.p[i] == 2)
              ci.p[i] = -1;
            else if (ci.p[i] == -2)
              ci.p[i] = 1;
        }
        
        // Count the number of 1's, -1's, and 0's in ci. Fail if any
        // count is less than dm0.
        if (!check_dm0(ci, keyParams.dm0))
          fail = true;

        // Calculate the candidate for r*h: cR = e - ci;
        FullPolynomial cR = FullPolynomial.subtract(e, ci, keyParams.q);

        // Calculate cR4 = cR mod 4
        // Generate masking polynomial mask by calling the given MGF with
        // inputs (cR4, N, minCallsMask
        FullPolynomial mask = calcEncryptionMask(cR);

        // Form cMtrin by polynomial subtraction of cm' and mask mod p
        // Note: cm' is actually called ci everywhere else in the spec.
        FullPolynomial cMtrin = 
          FullPolynomial.subtractAndRecenter(ci, mask, keyParams.p, -1);

        // Convert cMtrin to cMbin. Discard trailing bits
        byte cM[] = convPolyTrinaryToBinary(cMtrin);

        // Parse cMbin as b || l || m || p0. Fail if does not match.
        int mOffset = (keyParams.db)/8 + keyParams.lLen;
        int mLen = verifyMFormat(cM);
        if (mLen < 0)
        {
            // Set mLen to 1 so that later steps won't have to deal
            // with an invalid value.
            mLen = 1;
            fail = true;
        }

        // Form sData from OID, m, b, hTrunc
        // Note: b is the leading bytes of cM.
        byte sData[] = form_sData(cM, mOffset, mLen, cM, 0);

        // Calc cr from sData
        IGF2 igf = new IGF2(
            keyParams.N, keyParams.c, keyParams.igfHash, keyParams.minCallsR, 
            sData, 0, sData.length);
        FullPolynomial cr = BPGM3.genTrinomial(
            keyParams.N, keyParams.dr, keyParams.dr, igf);
        igf.close();

        // Calculate cR' = h * cr mod q
        FullPolynomial cRPrime = FullPolynomial.convolution(cr, h, keyParams.q);
        // If cR != cR', fail
        if (!cR.equals(cRPrime))
          fail = true;

        if (fail)
          throw new DecryptionFailureException();

        // Return message
        byte message[] = new byte[mLen];
        System.arraycopy(cM, mOffset, message, 0, mLen);
        return message;
    }


    /* generateM
     *
     * Calculate M = b | mLen | m | p0.
     */
    byte[] generateM(
        byte         message[],
        InputStream  rng)
    {
        // For now assume keyParams.lLen == 1
        // For now leave out RNG.
        int db = keyParams.db >> 3; // convert numBits to numBytes.
        int MLen = db + keyParams.lLen + keyParams.maxMsgLenBytes + 1;
        byte M[] = new byte[MLen];
        try {rng.read(M, 0, db);}
        catch (IOException e)
        {throw new InternalError("PRNG was unable to generate data");}

        M[db] = (byte) message.length;
        System.arraycopy(message, 0, M, db+keyParams.lLen, message.length);
        Arrays.fill(M, db+keyParams.lLen+message.length, M.length, (byte)0);
        return M;
    }



    /* convPolyBinaryToTrinaryHelper(
     *
     * Convert 3 bits into 2 trits.
     * The input bits are the least significant bits of b.
     * The outputs are stored in poly[offset] and poly[offset+1],
     * but in no case will anything be stored at an offset larger
     * than maxOffset.
     */
    void convPolyBinaryToTrinaryHelper(
        int   maxOffset,
        int   offset,
        short poly[],
        int   b)
    {
        byte a1 = 0, a2 = 0;
        switch (b & 0x07)
        {
          case (0) : a1 =  0; a2 =  0; break;
          case (1) : a1 =  0; a2 =  1; break;
          case (2) : a1 =  0; a2 = -1; break;
          case (3) : a1 =  1; a2 =  0; break;
          case (4) : a1 =  1; a2 =  1; break;
          case (5) : a1 =  1; a2 = -1; break;
          case (6) : a1 = -1; a2 =  0; break;
          case (7) : a1 = -1; a2 =  1; break;
        }
        if (offset < maxOffset)
          poly[offset++] = a1;
        if (offset < maxOffset)
          poly[offset] = a2;
    }

    /* convPolyBinaryToTrinaryHelper2(
     *
     * Convert 24 bits stored in bits24 into 8 trits.
     * The trits will be stored in poly[offset,...,offset+7], but
     * in no case will anything be written beyond maxOffset.
     */
    void convPolyBinaryToTrinaryHelper2(
        int   maxOffset,
        int   offset,
        short poly[],
        int   bits24)
    {
        for (int i=0; ((i<24) && (offset < maxOffset)); i+=3)
        {
            int shift = 24-(i+3);
            convPolyBinaryToTrinaryHelper(
                maxOffset, offset, poly, (bits24 >> shift));
            offset += 2;
        }
    }


    /* convPolyBinaryToTrinary(
     *
     * Convert a binary polynomial stored as a bit-packed array
     * into a trinomial with coefficients [-1, 0, 1] stored as an
     * array of shorts. Return the trinomial array.
     */
    short[] convPolyBinaryToTrinary(
        int  outputDegree,
        byte bin[])
    {
        short tri[] = new short[outputDegree];

        // Perform the bulk of the conversion in 3-byte blocks.
        // 3 bytes == 24 bits --> 16 trits.
        int blocks    = bin.length / 3;
        int remainder = bin.length % 3;
        for (int i=0; i<blocks; i++)
        {
            int val = (((0xff & bin[i*3])   << 16) |
                       ((0xff & bin[i*3+1]) << 8)  |
                       ( 0xff & bin[i*3+2]));
            convPolyBinaryToTrinaryHelper2(outputDegree, 16*i, tri, val);
        }

        // Convert any partial block left at the end of the input buffer
        int val = 0;
        if (remainder > 0)
          val |= (0xff & bin[blocks*3]   << 16);
        if (remainder > 1)
          val |= (0xff & bin[blocks*3+1] << 8);
        convPolyBinaryToTrinaryHelper2(outputDegree, 16*blocks, tri, val);

        // This shouldn't happen: if we need more trits than can be
        // generated from bin, pad with 0s.
        blocks++;
        if (16*blocks < outputDegree)
          java.util.Arrays.fill(tri, 16*blocks, outputDegree, (short)0);
        
        return tri;
    }


    /* convPolyTrinaryToBinaryHelper
     *
     * Convert 2 trits to 3 bits, using mapping defined in X9.92,
     * in the definition of the decryption algorithm.
     * Returns -1 if the input is not valid.
     */
    byte convPolyTritToBitHelper(
        int t1,
        int t2)
    {
        if (t1 == -1)
          t1 = 2;
        if (t2 == -1)
          t2 = 2;
        int t = ((t1 << 2) | t2);

        switch (t)
        {
          case (0)  : return 0x00;  //  (t1,t2)=( 0,  0)  ==>  t = 0000
          case (1)  : return 0x01;  //  (t1,t2)=( 0,  1)  ==>  t = 0001
          case (2)  : return 0x02;  //  (t1,t2)=( 0, -1)  ==>  t = 0010
          case (4)  : return 0x03;  //  (t1,t2)=( 1,  0)  ==>  t = 0100
          case (5)  : return 0x04;  //  (t1,t2)=( 1,  1)  ==>  t = 0101
          case (6)  : return 0x05;  //  (t1,t2)=( 1, -1)  ==>  t = 0110
          case (8)  : return 0x06;  //  (t1,t2)=(-1,  0)  ==>  t = 1000
          case (9)  : return 0x07;  //  (t1,t2)=(-1,  1)  ==>  t = 1001
          default   : return -1;    //  (t1,t2)=(-1, -1)  ==>  t = 1010
        }
    }

    /* convPolyTritToBitHelper
     *
     * Pull two trits out of the array of trits and convert them to a 3
     * bit value.
     */
    byte convPolyTritToBitHelper(
        int   offset,
        short trit[])
    {
        short t1 = 0, t2 = 0;
        if (offset < trit.length)
          t1 = trit[offset];
        if (offset+1 < trit.length)
          t2 = trit[offset+1];
        return convPolyTritToBitHelper(t1, t2);
    }

    boolean convPolyTrinaryToBinaryBlockHelper(
        int   tOffset,
        short trit[],
        int   bOffset,
        byte  bits[])
    {
        byte a1 = convPolyTritToBitHelper(tOffset, trit); tOffset += 2;
        byte a2 = convPolyTritToBitHelper(tOffset, trit); tOffset += 2;
        byte a3 = convPolyTritToBitHelper(tOffset, trit); tOffset += 2;
        byte a4 = convPolyTritToBitHelper(tOffset, trit); tOffset += 2;
        byte a5 = convPolyTritToBitHelper(tOffset, trit); tOffset += 2;
        byte a6 = convPolyTritToBitHelper(tOffset, trit); tOffset += 2;
        byte a7 = convPolyTritToBitHelper(tOffset, trit); tOffset += 2;
        byte a8 = convPolyTritToBitHelper(tOffset, trit); tOffset += 2;

        // Make sure there were no invalid trit combinations.
        if ((a1 | a2 | a3 | a4 | a5 | a6 | a7 | a8) == -1)
          return false;

        // Pack the 8 3-bit values into a single 32-bit integer.
        // This makes it easier to pull off bytes later.
        int val = ((a1 << 21) | (a2 << 18) | (a3 << 15) | (a4 << 12) |
                   (a5 << 9)  | (a6 << 6)  | (a7 << 3)  | a8);
        
        // Break the integer into bytes and put into the bits[] array.
        if (bOffset < bits.length)
          bits[bOffset++] = (byte)(val >> 16);
        if (bOffset < bits.length)
          bits[bOffset++] = (byte)(val >> 8);
        if (bOffset < bits.length)
          bits[bOffset++] = (byte)(val);

        return true;
    }
        
        
    byte[] convPolyTrinaryToBinary(
        FullPolynomial trin)
    {
        // The output of this operation is supposed to have
        // the form   (b | mLen | m | p0)  so we can
        // calculate how many bytes that is supposed to be.
        int numBytes = (keyParams.db/8 + keyParams.lLen +
                        keyParams.maxMsgLenBytes + 1);
        byte b[] = new byte[numBytes];
        int i=0, j=0;
        while (j<numBytes)
        {
            convPolyTrinaryToBinaryBlockHelper(i, trin.p, j, b);
            i += 16;
            j += 3;
        }
        return b;
    }

    /* form_sData
     *
     * Form the byte sequence sDaa = <OID | m | b | hTrunc>,
     * where hTrunc is a prefix of the bit-packed representtion of the
     * public key h.
     */ 
    byte[] form_sData(
        byte m[],
        int  mOffset,
        int  mLen,
        byte b[],
        int  bOffset)
    {
        int bLen = keyParams.db >> 3; // convert numBits to numBytes
        int hLen = keyParams.pkLen >> 3; // convert numBits to numBytes

        byte sData[] = new byte[
            keyParams.OIDBytes.length + mLen + bLen + hLen];
        int offset = 0;

        System.arraycopy(keyParams.OIDBytes, 0, sData, offset,keyParams.OIDBytes.length);
        offset += keyParams.OIDBytes.length;

        System.arraycopy(m, mOffset, sData, offset, mLen);
        offset += mLen;

        System.arraycopy(b, bOffset, sData, offset, bLen);
        offset += bLen;
        
        BitPack.pack(keyParams.N, keyParams.q, hLen, 
                     h.p, 0, sData, offset);
        return sData;
    }


    /* calcPolyMod4Packed(
     *
     * Calculate R mod 4 and return the result as a bit-packed byte
     * array.
     */
    byte[] calcPolyMod4Packed(
        FullPolynomial R)
    {
        // Calc R4 = R mod 4, 2 bits per element, 4 elements per byte
        byte R4[] = new byte[(R.p.length+3)/4];

        int i, j;
        for (i=0, j=0; i<R4.length-1; i++, j+=4)
          R4[i] = (byte) (((R.p[j] & 0x03) << 6) |
                          ((R.p[j+1] & 0x03) << 4) |
                          ((R.p[j+2] & 0x03) << 2) |
                          ((R.p[j+3] & 0x03)));

        int remElements = R.p.length % 4;
        R4[i] = 0;
        if (remElements > 0)
          R4[i] |= (byte) ((R.p[j++] & 0x03) << 6);
        if (remElements > 1)
          R4[i] |= (byte) ((R.p[j++] & 0x03) << 4);
        if (remElements > 2)
          R4[i] |= (byte) ((R.p[j++] & 0x03) << 2);

        return R4;
    }


    /* calcEncryptionMask
     *
     * Calculate the trinomial 'mask' using a bit-packed 'R mod 4' as
     * the seed of the MGF_TP_1 algorithm.
     */
    FullPolynomial calcEncryptionMask(
        FullPolynomial R)
    {
        byte R4[] = calcPolyMod4Packed(R);
        MGF1 mgf = new MGF1(keyParams.mgfHash, keyParams.minCallsMask, true,
                            R4, 0, R4.length);
        FullPolynomial p = MGF_TP_1.genTrinomial(keyParams.N, mgf);
        mgf.close();
        return p;
    }


    /* check_dm0
     *
     * Verify that the trinomial p has at least dm0 -1's, 
     * at least dm0 0's, and at least dm0 1's.
     */
    boolean check_dm0(
        FullPolynomial p,
        int            dm0)
    {
        int numOnes=0, numNegOnes=0;
        for (int i=0; i<p.p.length; i++)
        {
            short s = p.p[i];
            if (s == -1)
              numNegOnes++;
            else if (s == 1)
              numOnes += 1;
        }
        if ((numOnes < dm0) ||
            (numNegOnes < dm0) ||
            (p.p.length - (numOnes+numNegOnes) < dm0))
          return false;
        return true;
    }


    int parseMsgLengthFromM(
        byte M[])
    {
        int db = keyParams.db >> 3; // bits to bytes
        if (M.length < db + keyParams.lLen)
          return 0;
        int len = 0;
        for (int i=db; i<db + keyParams.lLen; i++)
          len = ((len << 8) | (M[i] & 0xff));
        return len;
    }


    int verifyMFormat(
        byte M[])
    {
        boolean ok = true;
        int db = keyParams.db>>3;

        // This is the number of bytes in the formatted message:
        int numBytes = (db + keyParams.lLen + keyParams.maxMsgLenBytes + 1);
        if (M.length != numBytes)
          ok = false;

        // 1) First db bytes are random data. Nothing to check there.

        // 2) Next lLen bytes are the message length. Decode this and
        //    verify it is valid.
        int mLen = 0;
        if (M.length >= db + keyParams.lLen)
          mLen = parseMsgLengthFromM(M);
        if ((mLen < 0) || (mLen >= keyParams.maxMsgLenBytes))
        {
            // Set mLen to 1 so that later steps won't have to worry
            // about invalid values.
            mLen = 1;
            ok = false;
        }

        // 3) Next mLen bytes are m. Nothing to verify there

        // 4) Remaining bytes are p0. Make sure they are all 0.
        for (int i=db + keyParams.lLen + mLen; (i<M.length); i++)
          if (M[i] != 0)
            ok = false;

        if (ok)
          return mLen;
        else
          return -1;
    }
}
