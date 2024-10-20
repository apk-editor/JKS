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
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import com.apk.jks.utils.DerOutputStream;
import com.apk.jks.utils.DerValue;

import androidx.annotation.NonNull;

public class AuthorityInfoAccessExtension extends Extension
        implements CertAttrSet<String> {

    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT =
                                "x509.info.extensions.AuthorityInfoAccess";

    /**
     * Attribute name.
     */
    public static final String NAME = "AuthorityInfoAccess";
    public static final String DESCRIPTIONS = "descriptions";

    /**
     * The List of AccessDescription objects.
     */
    private List<AccessDescription> accessDescriptions;

    /**
     * Create the extension from the passed DER encoded value of the same.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param value Array of DER encoded bytes of the actual value.
     * @exception IOException on error.
     */
    public AuthorityInfoAccessExtension(Boolean critical, Object value)
            throws IOException {
        this.extensionId = PKIXExtensions.AuthInfoAccess_Id;
        this.critical = critical;

        if (!(value instanceof byte[])) {
            throw new IOException("Illegal argument type");
        }

        extensionValue = (byte[])value;
        DerValue val = new DerValue(extensionValue);
        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding for " +
                                  "AuthorityInfoAccessExtension.");
        }
        accessDescriptions = new ArrayList<>();
        while (val.data.available() != 0) {
            DerValue seq = val.data.getDerValue();
            AccessDescription accessDescription = new AccessDescription(seq);
            accessDescriptions.add(accessDescription);
        }
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return NAME;
    }

    /**
     * Write the extension to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the extension to.
     * @exception IOException on encoding errors.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        if (this.extensionValue == null) {
            this.extensionId = PKIXExtensions.AuthInfoAccess_Id;
            this.critical = false;
            encodeThis();
        }
        super.encode(tmp);
        out.write(tmp.toByteArray());
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        if (name.equalsIgnoreCase(DESCRIPTIONS)) {
            if (!(obj instanceof List)) {
                throw new IOException("Attribute value should be of type List.");
            }
            accessDescriptions = (List<AccessDescription>)obj;
        } else {
            throw new IOException("Attribute name [" + name +
                                "] not recognized by " +
                                "CertAttrSet:AuthorityInfoAccessExtension.");
        }
        encodeThis();
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(DESCRIPTIONS)) {
            return accessDescriptions;
        } else {
            throw new IOException("Attribute name [" + name +
                                "] not recognized by " +
                                "CertAttrSet:AuthorityInfoAccessExtension.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(DESCRIPTIONS)) {
            accessDescriptions = new ArrayList<>();
        } else {
            throw new IOException("Attribute name [" + name +
                                "] not recognized by " +
                                "CertAttrSet:AuthorityInfoAccessExtension.");
        }
        encodeThis();
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getElements() {
        AttributeNameEnumeration elements = new AttributeNameEnumeration();
        elements.addElement(DESCRIPTIONS);
        return elements.elements();
    }

     // Encode this extension value
    private void encodeThis() throws IOException {
        if (accessDescriptions.isEmpty()) {
            this.extensionValue = null;
        } else {
            DerOutputStream ads = new DerOutputStream();
            for (AccessDescription accessDescription : accessDescriptions) {
                accessDescription.encode(ads);
            }
            DerOutputStream seq = new DerOutputStream();
            seq.write(DerValue.tag_Sequence, ads);
            this.extensionValue = seq.toByteArray();
        }
    }

    /**
     * Return the extension as user readable string.
     */
    @NonNull
    public String toString() {
        return super.toString() + "AuthorityInfoAccess [\n  "
               + accessDescriptions + "\n]\n";
    }

}