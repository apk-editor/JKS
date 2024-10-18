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

import java.io.IOException;
import java.io.OutputStream;
import java.util.Enumeration;

import com.apk.jks.utils.DerValue;
import com.apk.jks.utils.DerOutputStream;

import androidx.annotation.NonNull;

public class CertificateIssuerExtension extends Extension
    implements CertAttrSet<String> {

    /**
     * Attribute names.
     */
    public static final String NAME = "CertificateIssuer";
    public static final String ISSUER = "issuer";

    private GeneralNames names;

    /**
     * Encode this extension
     */
    private void encodeThis() throws IOException {
        if (names == null || names.isEmpty()) {
            this.extensionValue = null;
            return;
        }
        DerOutputStream os = new DerOutputStream();
        names.encode(os);
        this.extensionValue = os.toByteArray();
    }

    /**
     * Create a CertificateIssuerExtension from the specified DER encoded
     * value of the same.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param value an array of DER encoded bytes of the actual value
     * @throws ClassCastException if value is not an array of bytes
     * @throws IOException on error
     */
    public CertificateIssuerExtension(Boolean critical, Object value)
        throws IOException {
        this.extensionId = PKIXExtensions.CertificateIssuer_Id;
        this.critical = critical;

        this.extensionValue = (byte[]) value;
        DerValue val = new DerValue(this.extensionValue);
        this.names = new GeneralNames(val);
    }

    /**
     * Set the attribute value.
     *
     * @throws IOException on error
     */
    public void set(String name, Object obj) throws IOException {
        if (name.equalsIgnoreCase(ISSUER)) {
            if (!(obj instanceof GeneralNames)) {
                throw new IOException("Attribute value must be of type " +
                    "GeneralNames");
            }
            this.names = (GeneralNames)obj;
        } else {
            throw new IOException("Attribute name not recognized by " +
                "CertAttrSet:CertificateIssuer");
        }
        encodeThis();
    }

    /**
     * Gets the attribute value.
     *
     * @throws IOException on error
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(ISSUER)) {
            return names;
        } else {
            throw new IOException("Attribute name not recognized by " +
                "CertAttrSet:CertificateIssuer");
        }
    }

    /**
     * Deletes the attribute value.
     *
     * @throws IOException on error
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(ISSUER)) {
            names = null;
        } else {
            throw new IOException("Attribute name not recognized by " +
                "CertAttrSet:CertificateIssuer");
        }
        encodeThis();
    }

    /**
     * Returns a printable representation of the certificate issuer.
     */
    @NonNull
    public String toString() {
        return super.toString() + "Certificate Issuer [\n" + names + "]\n";
    }

    /**
     * Write the extension to the OutputStream.
     *
     * @param out the OutputStream to write the extension to
     * @exception IOException on encoding errors
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream  tmp = new DerOutputStream();
        if (extensionValue == null) {
            extensionId = PKIXExtensions.CertificateIssuer_Id;
            critical = true;
            encodeThis();
        }
        super.encode(tmp);
        out.write(tmp.toByteArray());
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getElements() {
        AttributeNameEnumeration elements = new AttributeNameEnumeration();
        elements.addElement(ISSUER);
        return elements.elements();
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return NAME;
    }
}