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

package com.apk.jks.pkcs;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Hashtable;
import com.apk.jks.utils.DerEncoder;
import com.apk.jks.utils.DerValue;
import com.apk.jks.utils.DerInputStream;
import com.apk.jks.utils.DerOutputStream;
import com.apk.jks.utils.ObjectIdentifier;

import androidx.annotation.NonNull;

public class PKCS9Attributes {
    /**
     * Attributes in this set indexed by OID.
     */
    private final Hashtable<ObjectIdentifier, PKCS9Attribute> attributes =
            new Hashtable<>(3);

    /**
     * The keys of this hashtable are the OIDs of permitted attributes.
     */
    private final Hashtable<ObjectIdentifier, ObjectIdentifier> permittedAttributes;

    /**
     * The DER encoding of this attribute set.  The tag byte must be
     * DerValue.tag_SetOf.
     */
    private final byte[] derEncoding;

    /*
     * Contols how attributes, which are not recognized by the PKCS9Attribute
     * class, are handled during parsing.
     */
    private final boolean ignoreUnsupportedAttributes;

    /**
     * Construct a set of PKCS9 Attributes from the contents of its
     * DER encoding on a DerInputStream.  Accept all attributes
     * supported by class PKCS9Attribute and reject any unsupported
     * attributes.
     *
     * @param in the contents of the DER encoding of the attribute set.
     * @exception IOException
     * on i/o error, encoding syntax error, or unsupported or
     * duplicate attribute.
     *
     * @see PKCS9Attribute
     */
    public PKCS9Attributes(DerInputStream in) throws IOException {
        this(in, false);
    }

    /**
     * Construct a set of PKCS9 Attributes from the contents of its
     * DER encoding on a DerInputStream.  Accept all attributes
     * supported by class PKCS9Attribute and ignore any unsupported
     * attributes, if directed.
     *
     * @param in the contents of the DER encoding of the attribute set.
     * @param ignoreUnsupportedAttributes If true then any attributes
     * not supported by the PKCS9Attribute class are ignored. Otherwise
     * unsupported attributes cause an exception to be thrown.
     * @exception IOException
     * on i/o error, encoding syntax error, or unsupported or
     * duplicate attribute.
     *
     * @see PKCS9Attribute
     */
    public PKCS9Attributes(DerInputStream in,
        boolean ignoreUnsupportedAttributes) throws IOException {

        this.ignoreUnsupportedAttributes = ignoreUnsupportedAttributes;
        // derEncoding initialized in <code>decode()</code>
        derEncoding = decode(in);
        permittedAttributes = null;
    }


    /**
     * Decode this set of PKCS9 attributes from the contents of its
     * DER encoding. Ignores unsupported attributes when directed.
     *
     * @param in
     * the contents of the DER encoding of the attribute set.
     *
     * @exception IOException
     * on i/o error, encoding syntax error, unacceptable or
     * unsupported attribute, or duplicate attribute.
     */
    private byte[] decode(DerInputStream in) throws IOException {

        DerValue val = in.getDerValue();

        // save the DER encoding with its proper tag byte.
        byte[] derEncoding = val.toByteArray();
        derEncoding[0] = DerValue.tag_SetOf;

        DerInputStream derIn = new DerInputStream(derEncoding);
        DerValue[] derVals = derIn.getSet(3,true);

        PKCS9Attribute attrib;
        ObjectIdentifier oid;
        boolean reuseEncoding = true;

        for (DerValue derVal : derVals) {

            try {
                attrib = new PKCS9Attribute(derVal);

            } catch (ParsingException e) {
                if (ignoreUnsupportedAttributes) {
                    reuseEncoding = false; // cannot reuse supplied DER encoding
                    continue; // skip
                } else {
                    throw e;
                }
            }
            oid = attrib.getOID();

            if (attributes.get(oid) != null)
                throw new IOException("Duplicate PKCS9 attribute: " + oid);

            if (permittedAttributes != null &&
                    !permittedAttributes.containsKey(oid))
                throw new IOException("Attribute " + oid +
                        " not permitted in this attribute set");

            attributes.put(oid, attrib);
        }
        return reuseEncoding ? derEncoding : generateDerEncoding();
    }

    /**
     * Put the DER encoding of this PKCS9 attribute set on an
     * DerOutputStream, tagged with the given implicit tag.
     *
     * @param tag the implicit tag to use in the DER encoding.
     * @param out the output stream on which to put the DER encoding.
     *
     * @exception IOException  on output error.
     */
    public void encode(byte tag, OutputStream out) throws IOException {
        out.write(tag);
        out.write(derEncoding, 1, derEncoding.length -1);
    }

    private byte[] generateDerEncoding() throws IOException {
        DerOutputStream out = new DerOutputStream();
        Object[] attribVals = attributes.values().toArray();

        out.putOrderedSetOf(DerValue.tag_SetOf,
                            castToDerEncoder(attribVals));
        return out.toByteArray();
    }

    /**
     * Return the DER encoding of this attribute set, tagged with
     * DerValue.tag_SetOf.
     */
    public byte[] getDerEncoding() throws IOException {
        return derEncoding.clone();

    }

    /**
     * Get an attribute from this set.
     */
    public PKCS9Attribute getAttribute(ObjectIdentifier oid) {
        return attributes.get(oid);
    }

    /**
     * Get an array of all attributes in this set, in order of OID.
     */
    public PKCS9Attribute[] getAttributes() {
        PKCS9Attribute[] attribs = new PKCS9Attribute[attributes.size()];

        int j = 0;
        for (int i=1; i < PKCS9Attribute.PKCS9_OIDS.length &&
                      j < attribs.length; i++) {
            attribs[j] = getAttribute(PKCS9Attribute.PKCS9_OIDS[i]);

            if (attribs[j] != null)
                j++;
        }
        return attribs;
    }

    /**
     * Get an attribute value by OID.
     */
    public Object getAttributeValue(ObjectIdentifier oid)
    throws IOException {
        try {
            return getAttribute(oid).getValue();
        } catch (NullPointerException ex) {
            throw new IOException("No value found for attribute " + oid);
        }

    }

    /**
     * Returns the PKCS9 block in a printable string form.
     */
    @NonNull
    public String toString() {
        StringBuilder buf = new StringBuilder(200);
        buf.append("PKCS9 Attributes: [\n\t");

        PKCS9Attribute value;

        boolean first = true;
        for (int i = 1; i < PKCS9Attribute.PKCS9_OIDS.length; i++) {
            value = getAttribute(PKCS9Attribute.PKCS9_OIDS[i]);

            if (value == null) continue;

            // we have a value; print it
            if (first)
                first = false;
            else
                buf.append(";\n\t");

            buf.append(value);
        }

        buf.append("\n\t] (end PKCS9 Attributes)");

        return buf.toString();
    }

    /**
     * Cast an object array whose components are
     * <code>DerEncoder</code>s to <code>DerEncoder[]</code>.
     */
    static DerEncoder[] castToDerEncoder(Object[] objs) {

        DerEncoder[] encoders = new DerEncoder[objs.length];

        for (int i=0; i < encoders.length; i++)
            encoders[i] = (DerEncoder) objs[i];

        return encoders;
    }
}