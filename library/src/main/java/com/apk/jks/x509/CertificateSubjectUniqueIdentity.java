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

import com.apk.jks.utils.DerValue;

import androidx.annotation.NonNull;

import com.apk.jks.utils.DerOutputStream;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Enumeration;

public class CertificateSubjectUniqueIdentity implements CertAttrSet<String> {
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.subjectID";
    /**
     * Sub attributes name for this CertAttrSet.
     */
    public static final String NAME = "subjectID";
    public static final String ID = "id";

    private UniqueIdentity id;

    /*
     * Create the object, decoding the values from the passed DER value.
     *
     * @param in the DerValue to read the UniqueIdentity from.
     * @exception IOException on decoding errors.
     */
    public CertificateSubjectUniqueIdentity(DerValue val)
    throws IOException {
        id = new UniqueIdentity(val);
    }

    /**
     * Return the identity as user readable string.
     */
    @NonNull
    public String toString() {
        if (id == null) return "";
        return(id.toString());
    }

    /**
     * Encode the identity in DER form to the stream.
     *
     * @param out the DerOutputStream to marshal the contents to.
     * @exception IOException on errors.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        id.encode(tmp, DerValue.createTag(DerValue.TAG_CONTEXT,false,(byte)2));

        out.write(tmp.toByteArray());
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        if (!(obj instanceof UniqueIdentity)) {
            throw new IOException("Attribute must be of type UniqueIdentity.");
        }
        if (name.equalsIgnoreCase(ID)) {
            id = (UniqueIdentity)obj;
        } else {
            throw new IOException("Attribute name not recognized by " +
                      "CertAttrSet: CertificateSubjectUniqueIdentity.");
        }
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(ID)) {
            return(id);
        } else {
            throw new IOException("Attribute name not recognized by " +
                      "CertAttrSet: CertificateSubjectUniqueIdentity.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(ID)) {
            id = null;
        } else {
            throw new IOException("Attribute name not recognized by " +
                      "CertAttrSet: CertificateSubjectUniqueIdentity.");
        }
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getElements() {
        AttributeNameEnumeration elements = new AttributeNameEnumeration();
        elements.addElement(ID);

        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }

}