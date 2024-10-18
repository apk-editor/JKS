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

public class NameConstraintsExtension extends Extension implements CertAttrSet<String>, Cloneable {
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.extensions.NameConstraints";
    /**
     * Attribute names.
     */
    public static final String NAME = "NameConstraints";
    public static final String PERMITTED_SUBTREES = "permitted_subtrees";
    public static final String EXCLUDED_SUBTREES = "excluded_subtrees";

    // Private data members
    private static final byte TAG_PERMITTED = 0;
    private static final byte TAG_EXCLUDED = 1;

    private GeneralSubtrees permitted = null;
    private GeneralSubtrees excluded = null;

    // Encode this extension value.
    private void encodeThis() throws IOException {
        if (permitted == null && excluded == null) {
            this.extensionValue = null;
            return;
        }
        DerOutputStream seq = new DerOutputStream();

        DerOutputStream tagged = new DerOutputStream();
        if (permitted != null) {
            DerOutputStream tmp = new DerOutputStream();
            permitted.encode(tmp);
            tagged.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT, true, TAG_PERMITTED), tmp);
        }
        if (excluded != null) {
            DerOutputStream tmp = new DerOutputStream();
            excluded.encode(tmp);
            tagged.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT, true, TAG_EXCLUDED), tmp);
        }
        seq.write(DerValue.tag_Sequence, tagged);
        this.extensionValue = seq.toByteArray();
    }

    /**
     * Create the extension from the passed DER encoded value.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param value    an array of DER encoded bytes of the actual value.
     * @throws ClassCastException if value is not an array of bytes
     * @throws IOException        on error.
     */
    public NameConstraintsExtension(Boolean critical, Object value) throws IOException {
        this.extensionId = PKIXExtensions.NameConstraints_Id;
        this.critical = critical;

        this.extensionValue = (byte[]) value;
        DerValue val = new DerValue(this.extensionValue);
        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding for NameConstraintsExtension.");
        }

        // NB. this is always encoded with the IMPLICIT tag
        // The checks only make sense if we assume implicit tagging,
        // with explicit tagging the form is always constructed.
        // Note that all the fields in NameConstraints are defined as
        // being OPTIONAL, i.e., there could be an empty SEQUENCE, resulting
        // in val.data being null.
        if (val.data == null)
            return;
        while (val.data.available() != 0) {
            DerValue opt = val.data.getDerValue();

            if (opt.isContextSpecific(TAG_PERMITTED) && opt.isConstructed()) {
                if (permitted != null) {
                    throw new IOException("Duplicate permitted GeneralSubtrees in NameConstraintsExtension.");
                }
                opt.resetTag(DerValue.tag_Sequence);
                permitted = new GeneralSubtrees(opt);

            } else if (opt.isContextSpecific(TAG_EXCLUDED) &&
                    opt.isConstructed()) {
                if (excluded != null) {
                    throw new IOException("Duplicate excluded GeneralSubtrees in NameConstraintsExtension.");
                }
                opt.resetTag(DerValue.tag_Sequence);
                excluded = new GeneralSubtrees(opt);
            } else
                throw new IOException("Invalid encoding of NameConstraintsExtension.");
        }
    }

    /**
     * Return the printable string.
     */
    @NonNull
    public String toString() {
        return (super.toString() + "NameConstraints: [" +
                ((permitted == null) ? "" : ("\n    Permitted:" + permitted)) +
                ((excluded == null) ? "" : ("\n    Excluded:" + excluded)) +
                "   ]\n");
    }

    /**
     * Write the extension to the OutputStream.
     *
     * @param out the OutputStream to write the extension to.
     * @throws IOException on encoding errors.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        if (this.extensionValue == null) {
            this.extensionId = PKIXExtensions.NameConstraints_Id;
            this.critical = true;
            encodeThis();
        }
        super.encode(tmp);
        out.write(tmp.toByteArray());
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        if (name.equalsIgnoreCase(PERMITTED_SUBTREES)) {
            if (!(obj instanceof GeneralSubtrees)) {
                throw new IOException("Attribute value should be of type GeneralSubtrees.");
            }
            permitted = (GeneralSubtrees) obj;
        } else if (name.equalsIgnoreCase(EXCLUDED_SUBTREES)) {
            if (!(obj instanceof GeneralSubtrees)) {
                throw new IOException("Attribute value should be of type GeneralSubtrees.");
            }
            excluded = (GeneralSubtrees) obj;
        } else {
            throw new IOException("Attribute name not recognized by CertAttrSet:NameConstraintsExtension.");
        }
        encodeThis();
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(PERMITTED_SUBTREES)) {
            return (permitted);
        } else if (name.equalsIgnoreCase(EXCLUDED_SUBTREES)) {
            return (excluded);
        } else {
            throw new IOException("Attribute name not recognized by CertAttrSet:NameConstraintsExtension.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(PERMITTED_SUBTREES)) {
            permitted = null;
        } else if (name.equalsIgnoreCase(EXCLUDED_SUBTREES)) {
            excluded = null;
        } else {
            throw new IOException("Attribute name not recognized by CertAttrSet:NameConstraintsExtension.");
        }
        encodeThis();
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getElements() {
        AttributeNameEnumeration elements = new AttributeNameEnumeration();
        elements.addElement(PERMITTED_SUBTREES);
        elements.addElement(EXCLUDED_SUBTREES);

        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }

    /**
     * check whether a name conforms to these NameConstraints.
     * This involves verifying that the name is consistent with the
     * permitted and excluded subtrees variables.
     *
     * @param name GeneralNameInterface name to be verified
     * @return true if certificate verifies successfully
     * @throws IOException on error
     */
    public boolean verify(GeneralNameInterface name) throws IOException {
        if (name == null) {
            throw new IOException("name is null");
        }

        // Verify that the name is consistent with the excluded subtrees
        if (excluded != null && excluded.size() > 0) {

            for (int i = 0; i < excluded.size(); i++) {
                GeneralSubtree gs = excluded.get(i);
                if (gs == null)
                    continue;
                GeneralName gn = gs.getName();
                if (gn == null)
                    continue;
                GeneralNameInterface exName = gn.getName();
                if (exName == null)
                    continue;

                // if name matches or narrows any excluded subtree,
                // return false
                switch (exName.constrains(name)) {
                    case GeneralNameInterface.NAME_DIFF_TYPE:
                    case GeneralNameInterface.NAME_WIDENS: // name widens excluded
                    case GeneralNameInterface.NAME_SAME_TYPE:
                        break;
                    case GeneralNameInterface.NAME_MATCH:
                    case GeneralNameInterface.NAME_NARROWS: // subject name excluded
                        return false;
                }
            }
        }

        // Verify that the name is consistent with the permitted subtrees
        if (permitted != null && permitted.size() > 0) {

            boolean sameType = false;

            for (int i = 0; i < permitted.size(); i++) {
                GeneralSubtree gs = permitted.get(i);
                if (gs == null)
                    continue;
                GeneralName gn = gs.getName();
                if (gn == null)
                    continue;
                GeneralNameInterface perName = gn.getName();
                if (perName == null)
                    continue;

                // if Name matches any type in permitted,
                // and Name does not match or narrow some permitted subtree,
                // return false
                switch (perName.constrains(name)) {
                    case GeneralNameInterface.NAME_DIFF_TYPE:
                        continue; // continue checking other permitted names
                    case GeneralNameInterface.NAME_WIDENS: // name widens permitted
                    case GeneralNameInterface.NAME_SAME_TYPE:
                        sameType = true;
                        continue; // continue to look for a match or narrow
                    case GeneralNameInterface.NAME_MATCH:
                    case GeneralNameInterface.NAME_NARROWS:
                        // name narrows permitted
                        return true; // name is definitely OK, so break out of loop
                }
            }
            return !sameType;
        }
        return true;
    }

    /**
     * Clone all objects that may be modified during certificate validation.
     */
    @NonNull
    public Object clone() {
        try {
            NameConstraintsExtension newNCE = (NameConstraintsExtension) super.clone();

            if (permitted != null) {
                newNCE.permitted = (GeneralSubtrees) permitted.clone();
            }
            if (excluded != null) {
                newNCE.excluded = (GeneralSubtrees) excluded.clone();
            }
            return newNCE;
        } catch (CloneNotSupportedException cnsee) {
            throw new RuntimeException("CloneNotSupportedException while cloning NameConstraintsException." +
                    " This should never happen.");
        }
    }
}