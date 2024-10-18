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
import com.apk.jks.utils.DerValue;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Enumeration;

public class AuthorityKeyIdentifierExtension extends Extension implements CertAttrSet<String> {
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT =
                         "x509.info.extensions.AuthorityKeyIdentifier";
    /**
     * Attribute names.
     */
    public static final String NAME = "AuthorityKeyIdentifier";
    public static final String KEY_ID = "key_id";
    public static final String AUTH_NAME = "auth_name";
    public static final String SERIAL_NUMBER = "serial_number";

    // Private data members
    private static final byte TAG_ID = 0;
    private static final byte TAG_NAMES = 1;
    private static final byte TAG_SERIAL_NUM = 2;

    private KeyIdentifier id = null;
    private GeneralNames names = null;
    private SerialNumber serialNum = null;

    // Encode only the extension value
    private void encodeThis() throws IOException {
        if (id == null && names == null && serialNum == null) {
            this.extensionValue = null;
            return;
        }
        DerOutputStream seq = new DerOutputStream();
        DerOutputStream tmp = new DerOutputStream();
        if (id != null) {
            DerOutputStream tmp1 = new DerOutputStream();
            id.encode(tmp1);
            tmp.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                              false, TAG_ID), tmp1);
        }
        try {
            if (names != null) {
                DerOutputStream tmp1 = new DerOutputStream();
                names.encode(tmp1);
                tmp.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                                  true, TAG_NAMES), tmp1);
            }
        } catch (Exception e) {
            throw new IOException(e.toString());
        }
        if (serialNum != null) {
            DerOutputStream tmp1 = new DerOutputStream();
            serialNum.encode(tmp1);
            tmp.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                              false, TAG_SERIAL_NUM), tmp1);
        }
        seq.write(DerValue.tag_Sequence, tmp);
        this.extensionValue = seq.toByteArray();
    }

    /**
     * Return the object as a string.
     */
    @NonNull
    public String toString() {
        String s = super.toString() + "AuthorityKeyIdentifier [\n";
        if (id != null) {
            s += id.toString();     // id already has a newline
        }
        if (names != null) {
            s += names + "\n";
        }
        if (serialNum != null) {
            s += serialNum + "\n";
        }
        return (s + "]\n");
    }

    /**
     * Write the extension to the OutputStream.
     *
     * @param out the OutputStream to write the extension to.
     * @exception IOException on error.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        if (this.extensionValue == null) {
            extensionId = PKIXExtensions.AuthorityKey_Id;
            critical = false;
            encodeThis();
        }
        super.encode(tmp);
        out.write(tmp.toByteArray());
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        if (name.equalsIgnoreCase(KEY_ID)) {
            if (!(obj instanceof KeyIdentifier)) {
              throw new IOException("Attribute value should be of " +
                                    "type KeyIdentifier.");
            }
            id = (KeyIdentifier)obj;
        } else if (name.equalsIgnoreCase(AUTH_NAME)) {
            if (!(obj instanceof GeneralNames)) {
              throw new IOException("Attribute value should be of " +
                                    "type GeneralNames.");
            }
            names = (GeneralNames)obj;
        } else if (name.equalsIgnoreCase(SERIAL_NUMBER)) {
            if (!(obj instanceof SerialNumber)) {
              throw new IOException("Attribute value should be of " +
                                    "type SerialNumber.");
            }
            serialNum = (SerialNumber)obj;
        } else {
          throw new IOException("Attribute name not recognized by " +
                        "CertAttrSet:AuthorityKeyIdentifier.");
        }
        encodeThis();
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(KEY_ID)) {
            return (id);
        } else if (name.equalsIgnoreCase(AUTH_NAME)) {
            return (names);
        } else if (name.equalsIgnoreCase(SERIAL_NUMBER)) {
            return (serialNum);
        } else {
          throw new IOException("Attribute name not recognized by " +
                        "CertAttrSet:AuthorityKeyIdentifier.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(KEY_ID)) {
            id = null;
        } else if (name.equalsIgnoreCase(AUTH_NAME)) {
            names = null;
        } else if (name.equalsIgnoreCase(SERIAL_NUMBER)) {
            serialNum = null;
        } else {
          throw new IOException("Attribute name not recognized by " +
                        "CertAttrSet:AuthorityKeyIdentifier.");
        }
        encodeThis();
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getElements() {
        AttributeNameEnumeration elements = new AttributeNameEnumeration();
        elements.addElement(KEY_ID);
        elements.addElement(AUTH_NAME);
        elements.addElement(SERIAL_NUMBER);

        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }
}