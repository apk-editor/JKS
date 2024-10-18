/*
 * Copyright (c) 1996, 2010, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package com.apk.jks.x509;

import com.apk.jks.utils.DerOutputStream;
import com.apk.jks.utils.ObjectIdentifier;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Enumeration;

public class InhibitAnyPolicyExtension extends Extension
implements CertAttrSet<String> {

    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.extensions.InhibitAnyPolicy";

    /**
     * Object identifier for "any-policy"
     */
    public static ObjectIdentifier AnyPolicy_Id;
    static {
        try {
            AnyPolicy_Id = new ObjectIdentifier("2.5.29.32.0");
        } catch (IOException ioe) {
            // Should not happen
        }
    }

    /**
     * Attribute names.
     */
    public static final String NAME = "InhibitAnyPolicy";
    public static final String SKIP_CERTS = "skip_certs";

    // Private data members
    private int skipCerts = Integer.MAX_VALUE;

    // Encode this extension value
    private void encodeThis() throws IOException {
        DerOutputStream out = new DerOutputStream();
        out.putInteger(skipCerts);
        this.extensionValue = out.toByteArray();
    }

     /**
      * Return user readable form of extension.
      */
     @NonNull
     public String toString() {
         return super.toString() + "InhibitAnyPolicy: " + skipCerts + "\n";
     }

     /**
      * Encode this extension value to the output stream.
      *
      * @param out the DerOutputStream to encode the extension to.
      */
     public void encode(OutputStream out) throws IOException {
         DerOutputStream tmp = new DerOutputStream();
         if (extensionValue == null) {
             this.extensionId = PKIXExtensions.InhibitAnyPolicy_Id;
             critical = true;
             encodeThis();
         }
         super.encode(tmp);

         out.write(tmp.toByteArray());
     }

    /**
     * Set the attribute value.
     *
     * @param name name of attribute to set. Must be SKIP_CERTS.
     * @param obj  value to which attribute is to be set.  Must be Integer
     *             type.
     * @throws IOException on error
     */
    public void set(String name, Object obj) throws IOException {
        if (name.equalsIgnoreCase(SKIP_CERTS)) {
            if (!(obj instanceof Integer))
                throw new IOException("Attribute value should be of type Integer.");
            int skipCertsValue = (Integer) obj;
            if (skipCertsValue < -1)
                throw new IOException("Invalid value for skipCerts");
            if (skipCertsValue == -1) {
                skipCerts = Integer.MAX_VALUE;
            } else {
                skipCerts = skipCertsValue;
            }
        } else
            throw new IOException("Attribute name not recognized by " +
                                  "CertAttrSet:InhibitAnyPolicy.");
        encodeThis();
    }

    /*
     * Get the attribute value.
     *
     * @param name name of attribute to get.  Must be SKIP_CERTS.
     * @returns value of the attribute.  In this case it will be of type
     *          Integer.
     * @throws IOException on error
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(SKIP_CERTS))
            return (skipCerts);
        else
            throw new IOException("Attribute name not recognized by " +
                                  "CertAttrSet:InhibitAnyPolicy.");
    }

    /**
     * Delete the attribute value.
     *
     * @param name name of attribute to delete. Must be SKIP_CERTS.
     * @throws IOException on error.  In this case, IOException will always be
     *                     thrown, because the only attribute, SKIP_CERTS, is
     *                     required.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(SKIP_CERTS))
            throw new IOException("Attribute " + SKIP_CERTS +
                                  " may not be deleted.");
        else
            throw new IOException("Attribute name not recognized by " +
                                  "CertAttrSet:InhibitAnyPolicy.");
    }

    /*
     * Return an enumeration of names of attributes existing within this
     * attribute.
     *
     * @returns enumeration of elements
     */
    public Enumeration<String> getElements() {
        AttributeNameEnumeration elements = new AttributeNameEnumeration();
        elements.addElement(SKIP_CERTS);
        return (elements.elements());
    }

    /*
     * Return the name of this attribute.
     *
     * @returns name of attribute.
     */
    public String getName() {
        return (NAME);
    }
}