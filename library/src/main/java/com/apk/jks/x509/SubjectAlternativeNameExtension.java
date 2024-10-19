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

import android.os.Build;

import com.apk.jks.utils.DerOutputStream;
import com.apk.jks.utils.DerValue;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Enumeration;

public class SubjectAlternativeNameExtension extends Extension
implements CertAttrSet<String> {
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT =
                         "x509.info.extensions.SubjectAlternativeName";
    /**
     * Attribute names.
     */
    public static final String NAME = "SubjectAlternativeName";
    public static final String SUBJECT_NAME = "subject_name";

    // private data members
    GeneralNames names;

    // Encode this extension
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
     * Create the extension from the passed DER encoded value.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param value an array of DER encoded bytes of the actual value.
     * @exception ClassCastException if value is not an array of bytes
     * @exception IOException on error.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public SubjectAlternativeNameExtension(Boolean critical, Object value)
    throws IOException {
        this.extensionId = PKIXExtensions.SubjectAlternativeName_Id;
        this.critical = critical;

        this.extensionValue = (byte[]) value;
        DerValue val = new DerValue(this.extensionValue);
        if (val.data == null) {
            names = new GeneralNames();
            return;
        }

        names = new GeneralNames(val);
    }

    /**
     * Returns a printable representation of the SubjectAlternativeName.
     */
    @NonNull
    public String toString() {

        StringBuilder result = new StringBuilder(super.toString() + "SubjectAlternativeName [\n");
        if(names == null) {
            result.append("  null\n");
        } else {
            for(GeneralName name: names.names()) {
                result.append("  ").append(name).append("\n");
            }
        }
        result.append("]\n");
        return result.toString();
    }

    /**
     * Write the extension to the OutputStream.
     *
     * @param out the OutputStream to write the extension to.
     * @exception IOException on encoding errors.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        if (extensionValue == null) {
            extensionId = PKIXExtensions.SubjectAlternativeName_Id;
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
        if (name.equalsIgnoreCase(SUBJECT_NAME)) {
            if (!(obj instanceof GeneralNames)) {
              throw new IOException("Attribute value should be of " +
                                    "type GeneralNames.");
            }
            names = (GeneralNames)obj;
        } else {
          throw new IOException("Attribute name not recognized by " +
                        "CertAttrSet:SubjectAlternativeName.");
        }
        encodeThis();
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(SUBJECT_NAME)) {
            return (names);
        } else {
          throw new IOException("Attribute name not recognized by " +
                        "CertAttrSet:SubjectAlternativeName.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(SUBJECT_NAME)) {
            names = null;
        } else {
          throw new IOException("Attribute name not recognized by " +
                        "CertAttrSet:SubjectAlternativeName.");
        }
        encodeThis();
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getElements() {
        AttributeNameEnumeration elements = new AttributeNameEnumeration();
        elements.addElement(SUBJECT_NAME);

        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }
}