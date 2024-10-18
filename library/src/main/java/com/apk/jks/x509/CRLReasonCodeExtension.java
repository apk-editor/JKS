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

import androidx.annotation.NonNull;

import com.apk.jks.utils.DerValue;

import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.CRLReason;
import java.util.Enumeration;

public class CRLReasonCodeExtension extends Extension implements CertAttrSet<String> {

    /**
     * Attribute name and Reason codes
     */
    public static final String NAME = "CRLReasonCode";
    public static final String REASON = "reason";

    private static final CRLReason[] values = CRLReason.values();

    private int reasonCode;

    private void encodeThis() throws IOException {
        if (reasonCode == 0) {
            this.extensionValue = null;
            return;
        }
        DerOutputStream dos = new DerOutputStream();
        dos.putEnumerated(reasonCode);
        this.extensionValue = dos.toByteArray();
    }

    /**
     * Create the extension from the passed DER encoded value of the same.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param value an array of DER encoded bytes of the actual value.
     * @exception ClassCastException if value is not an array of bytes
     * @exception IOException on error.
     */
    public CRLReasonCodeExtension(Boolean critical, Object value)
    throws IOException {
        this.extensionId = PKIXExtensions.ReasonCode_Id;
        this.critical = critical;
        this.extensionValue = (byte[]) value;
        DerValue val = new DerValue(this.extensionValue);
        this.reasonCode = val.getEnumerated();
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        if (!(obj instanceof Integer)) {
            throw new IOException("Attribute must be of type Integer.");
        }
        if (name.equalsIgnoreCase(REASON)) {
            reasonCode = (Integer) obj;
        } else {
            throw new IOException
                ("Name not supported by CRLReasonCodeExtension");
        }
        encodeThis();
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(REASON)) {
            return reasonCode;
        } else {
            throw new IOException
                ("Name not supported by CRLReasonCodeExtension");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(REASON)) {
            reasonCode = 0;
        } else {
            throw new IOException
                ("Name not supported by CRLReasonCodeExtension");
        }
        encodeThis();
    }

    /**
     * Returns a printable representation of the Reason code.
     */
    @NonNull
    public String toString() {
        return super.toString() + "    Reason Code: " + values[reasonCode];
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
            this.extensionId = PKIXExtensions.ReasonCode_Id;
            this.critical = false;
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
        elements.addElement(REASON);

        return elements.elements();
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return NAME;
    }

    /**
     * Return the reason as a CRLReason enum.
     *
     * @throws UnsupportedOperationException If the Android API version is less than 24 and
     *                                       no valid reason has been found.
     */
    public CRLReason getReasonCode() {
        // if out-of-range, return UNSPECIFIED
        if (reasonCode > 0 && reasonCode < values.length) {
            return values[reasonCode];
        } else {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                return CRLReason.UNSPECIFIED;
            } else throw new UnsupportedOperationException("Invalid reason.");
        }
    }
}