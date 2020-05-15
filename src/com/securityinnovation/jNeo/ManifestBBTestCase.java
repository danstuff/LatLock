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

import org.junit.Test;
import static org.junit.Assert.*;

import java.util.jar.*;

public class ManifestBBTestCase
{
    static String jarfileName = "jars/jNeo.jar";

    String getAttribute(
        String attrName)
        throws java.io.IOException
    {
        JarFile jarfile = new JarFile(jarfileName);
        Manifest manifest = jarfile.getManifest();
        Attributes att = manifest.getMainAttributes();
        return att.getValue(attrName);
    }

    @Test public void test_implementation_vendor()
        throws java.io.IOException
    {
        assertEquals("Security Innovation",
                     getAttribute("Implementation-Vendor"));
    }
    
    @Test public void test_implementation_title()
        throws java.io.IOException
    {
        assertEquals("jNeo",
                     getAttribute("Implementation-Title"));
    }
    
    @Test public void test_implementation_version()
        throws java.io.IOException
    {
        assertEquals("1.0rc1",
                     getAttribute("Implementation-Version"));
    }
    
}
