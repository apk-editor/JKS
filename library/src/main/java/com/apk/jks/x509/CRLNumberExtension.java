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

import com.apk.jks.utils.ObjectIdentifier;

import androidx.annotation.NonNull;

import com.apk.jks.utils.Debug;
import com.apk.jks.utils.DerOutputStream;
import com.apk.jks.utils.DerValue;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Enumeration;

public class CRLNumberExtension extends Extension implements CertAttrSet<String> {

    /**
     * Attribute name.
     */
    public static final String NAME = "CRLNumber";
    public static final String NUMBER = "value";

    private BigInteger crlNumber;
    private final String extensionName;
    private final String extensionLabel;

    // Encode this extension value
    private void encodeThis() throws IOException {
        if (crlNumber == null) {
            this.extensionValue = null;
            return;
        }
        DerOutputStream os = new DerOutputStream();
        os.putInteger(this.crlNumber);
        this.extensionValue = os.toByteArray();
    }

    /**
     * Creates the extension (also called by the subclass).
     */
    protected CRLNumberExtension(ObjectIdentifier extensionId,
                                 boolean isCritical, BigInteger crlNum, String extensionName,
                                 String extensionLabel) throws IOException {

        this.extensionId = extensionId;
        this.critical = isCritical;
        this.crlNumber = crlNum;
        this.extensionName = extensionName;
        this.extensionLabel = extensionLabel;
        encodeThis();
    }

    /**
     * Creates the extension (also called by the subclass).
     */
    protected CRLNumberExtension(ObjectIdentifier extensionId,
                                 Boolean critical, Object value, String extensionName,
                                 String extensionLabel) throws IOException {

        this.extensionId = extensionId;
        this.critical = critical;
        this.extensionValue = (byte[]) value;
        DerValue val = new DerValue(this.extensionValue);
        this.crlNumber = val.getBigInteger();
        this.extensionName = extensionName;
        this.extensionLabel = extensionLabel;
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        if (name.equalsIgnoreCase(NUMBER)) {
            if (!(obj instanceof BigInteger)) {
                throw new IOException("Attribute must be of type BigInteger.");
            }
            crlNumber = (BigInteger)obj;
        } else {
          throw new IOException("Attribute name not recognized by"
                                + " CertAttrSet:" + extensionName + ".");
        }
        encodeThis();
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(NUMBER)) {
            if (crlNumber == null) return null;
            else return crlNumber;
        } else {
          throw new IOException("Attribute name not recognized by"
                                + " CertAttrSet:" + extensionName + ".");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(NUMBER)) {
            crlNumber = null;
        } else {
          throw new IOException("Attribute name not recognized by"
                                + " CertAttrSet:" + extensionName + ".");
        }
        encodeThis();
    }

    /**
     * Returns a printable representation of the CRLNumberExtension.
     */
    @NonNull
    public String toString() {
        return (super.toString() + extensionLabel + ": " +
                   ((crlNumber == null) ? "" : Debug.toHexString(crlNumber))
                   + "\n");
    }

    /**
     * Write the extension to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the extension to.
     * @exception IOException on encoding errors.
     */
    public void encode(OutputStream out) throws IOException {
        encode(out, PKIXExtensions.CRLNumber_Id, true);
    }

    /**
     * Write the extension to the DerOutputStream.
     * (Also called by the subclass)
     */
    protected void encode(OutputStream out, ObjectIdentifier extensionId,
        boolean isCritical) throws IOException {

       DerOutputStream tmp = new DerOutputStream();

       if (this.extensionValue == null) {
           this.extensionId = extensionId;
           this.critical = isCritical;
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
        elements.addElement(NUMBER);
        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (extensionName);
    }

}