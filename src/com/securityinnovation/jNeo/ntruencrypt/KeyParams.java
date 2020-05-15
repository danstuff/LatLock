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

import com.securityinnovation.jNeo.OID;
import com.securityinnovation.jNeo.OIDMap;
import com.securityinnovation.jNeo.ParamSetNotSupportedException;
import com.securityinnovation.jNeo.digest.DigestAlgorithm;
import static com.securityinnovation.jNeo.digest.DigestAlgorithm.*;
import com.securityinnovation.jNeo.math.PolynomialInverter;
import com.securityinnovation.jNeo.math.PolynomialInverterModPowerOfPrime;

/**
 * <p>A class to collect information on an encryption parameter set.
 * An instance of this class holds the data for a single parameter set
 * in its public members.
 *
 * <p>The static function getKeyParams() can be used to retrieve the
 * KeyParams object associated with a particular parameter set (using
 * the OID as an identifier). The returned object is static and should
 * be treated as read-only.
 */
public class KeyParams
{
    public final OID   OIDEnum;
    public final byte  OIDBytes[];
    public final short N;
    public final short p;
    public final short q;
    public final short df;
    public final short dg;
    public final short lLen;
    public final short db;
    public final short maxMsgLenBytes;
    public final short bufferLenBits;
    public final short bufferLenTrits;
    public final short dm0;

    // Mask generation params, used in the generation of mask from R mod 4.
    public final DigestAlgorithm mgfHash;

    // BPGM3 params
    public final DigestAlgorithm igfHash;
    public final short dr;
    public final short c;
    public final short minCallsR;
    public final short minCallsMask;

    public final int pkLen;

    // The code to use to find the inverse of a polynomial.
    public final PolynomialInverter polyInverter;


    /**
     * Returns the KeyParams object for the specified OID, as
     * represented by a byte array.
     *
     * @param paramSet a byte array holding the OID.
     *
     * @throws ParamsetNotSupportedException if the OID is not known.
     */
    public static KeyParams getKeyParams(
        byte[] paramSet)
        throws ParamSetNotSupportedException
    {
        if (numParamSets == 0)
          initParamSets();
        for (int i=0; i<numParamSets; i++)
          if (java.util.Arrays.equals(paramSets[i].OIDBytes, paramSet))
            return paramSets[i];
        throw new ParamSetNotSupportedException(paramSet);
    }


    /**
     * Returns the KeyParams object for the specified OID, as
     * represented by a byte array.
     *
     * @param paramSet the OID identifying the parameter set.
     *
     * @throws ParamsetNotSupportedException if the OID is not known.
     */
    public static KeyParams getKeyParams(
        OID paramSet)
        throws ParamSetNotSupportedException
    {
        if (numParamSets == 0)
          initParamSets();
        for (int i=0; i<numParamSets; i++)
          if (paramSet == paramSets[i].OIDEnum)
            return paramSets[i];
        throw new ParamSetNotSupportedException(paramSet);
    }



    /**
     * Constructor.
     */
    private KeyParams(
        OID _oidEnum,
        int  _N,
        int  _p,
        int  _q,
        int  _df,
        int  _dg,
        int  _lLen,
        int  _db,
        int  _maxMsgLenBytes,
        int  _bufferLenBits,
        int  _bufferLenTrits,
        int  _dm0,
        DigestAlgorithm _mgfHash,
        DigestAlgorithm _igfHash,
        int  _dr,
        int  _c,
        int  _minCallsR,
        int  _minCallsMask,
        int  _pkLen)
    {
        OIDEnum = _oidEnum;
        OIDBytes = OIDMap.getOIDBytes(OIDEnum);
        N = (short) _N;
        p = (short) _p;
        q = (short) _q;
        df = (short) _df;
        dg = (short) _dg;
        lLen = (short) _lLen;
        db = (short) _db;
        maxMsgLenBytes = (short) _maxMsgLenBytes;
        bufferLenBits = (short) _bufferLenBits;
        bufferLenTrits = (short) _bufferLenTrits;
        dm0 = (short) _dm0;
        mgfHash = _mgfHash;
        igfHash = _igfHash;
        dr = (short) _dr;
        c = (short) _c;
        minCallsR = (short) _minCallsR;
        minCallsMask = (short) _minCallsMask;
        pkLen = _pkLen;

        // This should be derived from q. But for now all parameter sets use
        // q = 2048.        
        polyInverter = inverterMod2048;
    }


    // An object to find the inverse of a polynomial mod 2048
    // and a table of inverses mod 2 needed to construct the inverter.
    private static short invMod2[] = {0, 1};
    private static PolynomialInverter inverterMod2048 = 
      new PolynomialInverterModPowerOfPrime(2048, 2, invMod2);

    // The master list of parameter sets.
    private static KeyParams paramSets[];
    private static byte      numParamSets = 0;
    private static void initParamSets()
    {
        paramSets = new KeyParams[12];
        paramSets[numParamSets++] = 
          new KeyParams(
              OID.ees401ep1, 401, 3, 2048,    // id, N, p, q
              113, 133, 1, 112,               // df, dg. lLen, db
              60,                             // maxMsgLenBytes,
              600, 400,                       // bufferLenBits, bufferLenTrits
              113,                            // dm0
              sha1, sha1,                     // mgfHash, igfHash
              113, 11, 32, 9,                 // dr, c, minCallsR, minCallsMask
              112);                           // pkLen
        paramSets[numParamSets++] = 
          new KeyParams(
              OID.ees449ep1, 449, 3, 2048,    // id, N, p, q
              134, 149, 1, 128,               // df, dg. lLen, db
              67,                             // maxMsgLenBytes,
              672, 448,                       // bufferLenBits, bufferLenTrits
              134,                            // dm0
              sha1, sha1,                     // mgfHash, igfHash
              134, 9, 31, 9,                  // dr, c, minCallsR, minCallsMask
              128);                           // pkLen
        paramSets[numParamSets++] = 
          new KeyParams(
              OID.ees677ep1, 677, 3, 2048,    // id, N, p, q
              157, 225, 1, 192,               // df, dg. lLen, db
              101,                            // maxMsgLenBytes,
              1008, 676,                      // bufferLenBits, bufferLenTrits
              157,                            // dm0
              sha256, sha256,                 // mgfHash, igfHash
              157, 11, 27, 9,                 // dr, c, minCallsR, minCallsMask
              192);                           // pkLen
        paramSets[numParamSets++] = 
          new KeyParams(
              OID.ees1087ep2, 1087, 3, 2048,  // id, N, p, q
              120, 362, 1, 256,               // df, dg. lLen, db
              170,                            // maxMsgLenBytes,
              1624, 1086,                     // bufferLenBits, bufferLenTrits
              120,                            // dm0
              sha256, sha256,                 // mgfHash, igfHash
              120, 13, 25, 14,                // dr, c, minCallsR, minCallsMask
              256);                           // pkLen
        paramSets[numParamSets++] = 
          new KeyParams(
              OID.ees541ep1, 541, 3, 2048,    // id, N, p, q
              49, 180, 1, 112,                // df, dg. lLen, db
              86,                             // maxMsgLenBytes,
              808, 540,                       // bufferLenBits, bufferLenTrits
              49,                             // dm0
              sha1, sha1,                     // mgfHash, igfHash
              49, 12, 15, 11,                 // dr, c, minCallsR, minCallsMask
              112);                           // pkLen
        paramSets[numParamSets++] = 
          new KeyParams(
              OID.ees613ep1, 613, 3, 2048,    // id, N, p, q
              55, 204, 1, 128,                // df, dg. lLen, db
              97,                             // maxMsgLenBytes,
              912, 612,                       // bufferLenBits, bufferLenTrits
              55,                             // dm0
              sha1, sha1,                     // mgfHash, igfHash
              55, 11, 16, 13,                 // dr, c, minCallsR, minCallsMask
              128);                           // pkLen
        paramSets[numParamSets++] = 
          new KeyParams(
              OID.ees887ep1, 887, 3, 2048,    // id, N, p, q
              81, 295, 1, 192,                // df, dg. lLen, db
              141,                            // maxMsgLenBytes,
              1328, 886,                      // bufferLenBits, bufferLenTrits
              81,                             // dm0
              sha256, sha256,                 // mgfHash, igfHash
              81, 10, 13, 12,                 // dr, c, minCallsR, minCallsMask
              192);                           // pkLen
        paramSets[numParamSets++] = 
          new KeyParams(
              OID.ees1171ep1, 1171, 3, 2048,  // id, N, p, q
              106, 390, 1, 256,               // df, dg. lLen, db
              186,                            // maxMsgLenBytes,
              1752, 1170,                     // bufferLenBits, bufferLenTrits
              106,                            // dm0
              sha256, sha256,                 // mgfHash, igfHash
              106, 12, 20, 15,                // dr, c, minCallsR, minCallsMask
              256);                           // pkLen
        paramSets[numParamSets++] = 
          new KeyParams(
              OID.ees659ep1, 659, 3, 2048,    // id, N, p, q
              38, 219, 1, 112,                // df, dg. lLen, db
              108,                            // maxMsgLenBytes,
              984, 658,                       // bufferLenBits, bufferLenTrits
              38,                             // dm0
              sha1, sha1,                     // mgfHash, igfHash
              38, 11, 11, 14,                 // dr, c, minCallsR, minCallsMask
              112);                           // pkLen
        paramSets[numParamSets++] = 
          new KeyParams(
              OID.ees761ep1, 761, 3, 2048,    // id, N, p, q
              42, 253, 1, 128,                // df, dg. lLen, db
              125,                            // maxMsgLenBytes,
              1136, 760,                      // bufferLenBits, bufferLenTrits
              42,                             // dm0
              sha1, sha1,                     // mgfHash, igfHash
              42, 12, 13, 16,                 // dr, c, minCallsR, minCallsMask
              128);                           // pkLen
        paramSets[numParamSets++] = 
          new KeyParams(
              OID.ees1087ep1, 1087, 3, 2048,  // id, N, p, q
              63, 362, 1, 192,                // df, dg. lLen, db
              178,                            // maxMsgLenBytes,
              1624, 1086,                     // bufferLenBits, bufferLenTrits
              63,                             // dm0
              sha256, sha256,                 // mgfHash, igfHash
              63, 13, 13, 14,                 // dr, c, minCallsR, minCallsMask
              192);                           // pkLen
        paramSets[numParamSets++] = 
          new KeyParams(
              OID.ees1499ep1, 1499, 3, 2048,  // id, N, p, q
              79, 499, 1, 256,                // df, dg. lLen, db
              247,                            // maxMsgLenBytes,
              2240, 1498,                     // bufferLenBits, bufferLenTrits
              79,                             // dm0
              sha256, sha256,                 // mgfHash, igfHash
              79, 13, 17, 19,                 // dr, c, minCallsR, minCallsMask
              256);                           // pkLen
    }
}
