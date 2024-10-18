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

import androidx.annotation.NonNull;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Enumeration;

import com.apk.jks.utils.DerOutputStream;
import com.apk.jks.utils.DerValue;

public class PolicyConstraintsExtension extends Extension implements CertAttrSet<String> {
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.extensions.PolicyConstraints";
    /**
     * Attribute names.
     */
    public static final String NAME = "PolicyConstraints";
    public static final String REQUIRE = "require";
    public static final String INHIBIT = "inhibit";

    private static final byte TAG_REQUIRE = 0;
    private static final byte TAG_INHIBIT = 1;

    private int require = -1;
    private int inhibit = -1;

    // Encode this extension value.
    private void encodeThis() throws IOException {
        if (require == -1 && inhibit == -1) {
            this.extensionValue = null;
            return;
        }
        DerOutputStream tagged = new DerOutputStream();
        DerOutputStream seq = new DerOutputStream();

        if (require != -1) {
            DerOutputStream tmp = new DerOutputStream();
            tmp.putInteger(require);
            tagged.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                         false, TAG_REQUIRE), tmp);
        }
        if (inhibit != -1) {
            DerOutputStream tmp = new DerOutputStream();
            tmp.putInteger(inhibit);
            tagged.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                         false, TAG_INHIBIT), tmp);
        }
        seq.write(DerValue.tag_Sequence, tagged);
        this.extensionValue = seq.toByteArray();
    }

    /**
     * Return the extension as user readable string.
     */
    @NonNull
    public String toString() {
        String s;
        s = super.toString() + "PolicyConstraints: [" + "  Require: ";
        if (require == -1)
            s += "unspecified;";
        else
            s += require + ";";
        s += "\tInhibit: ";
        if (inhibit == -1)
            s += "unspecified";
        else
            s += inhibit;
        s += " ]\n";
        return s;
    }

    /**
     * Write the extension to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the extension to.
     * @exception IOException on encoding errors.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        if (extensionValue == null) {
          extensionId = PKIXExtensions.PolicyConstraints_Id;
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
        if (!(obj instanceof Integer)) {
            throw new IOException("Attribute value should be of type Integer.");
        }
        if (name.equalsIgnoreCase(REQUIRE)) {
            require = (Integer) obj;
        } else if (name.equalsIgnoreCase(INHIBIT)) {
            inhibit = (Integer) obj;
        } else {
          throw new IOException("Attribute name " + "[" + name + "]" +
                                " not recognized by " +
                                "CertAttrSet:PolicyConstraints.");
        }
        encodeThis();
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(REQUIRE)) {
            return require;
        } else if (name.equalsIgnoreCase(INHIBIT)) {
            return inhibit;
        } else {
          throw new IOException("Attribute name not recognized by " +
                                "CertAttrSet:PolicyConstraints.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(REQUIRE)) {
            require = -1;
        } else if (name.equalsIgnoreCase(INHIBIT)) {
            inhibit = -1;
        } else {
          throw new IOException("Attribute name not recognized by " +
                                "CertAttrSet:PolicyConstraints.");
        }
        encodeThis();
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getElements() {
        AttributeNameEnumeration elements = new AttributeNameEnumeration();
        elements.addElement(REQUIRE);
        elements.addElement(INHIBIT);

        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }
}