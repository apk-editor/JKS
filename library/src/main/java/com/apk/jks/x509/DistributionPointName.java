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
import java.util.Objects;

import com.apk.jks.utils.DerOutputStream;
import com.apk.jks.utils.DerValue;

import androidx.annotation.NonNull;

public class DistributionPointName {

    // ASN.1 context specific tag values
    private static final byte TAG_FULL_NAME = 0;
    private static final byte TAG_RELATIVE_NAME = 1;

    // Only one of fullName and relativeName can be set
    private GeneralNames fullName = null;
    private RDN relativeName = null;

    // Cached hashCode value
    private volatile int hashCode;

    /**
     * Creates a distribution point name from its DER-encoded form.
     *
     * @param encoding the DER-encoded value.
     * @throws IOException on decoding error.
     */
    public DistributionPointName(DerValue encoding) throws IOException {

        if (encoding.isContextSpecific(TAG_FULL_NAME) &&
            encoding.isConstructed()) {

            encoding.resetTag(DerValue.tag_Sequence);
            fullName = new GeneralNames(encoding);

        } else if (encoding.isContextSpecific(TAG_RELATIVE_NAME) &&
            encoding.isConstructed()) {

            encoding.resetTag(DerValue.tag_Set);
            relativeName = new RDN(encoding);

        } else {
            throw new IOException("Invalid encoding for DistributionPointName");
        }

    }

    /**
     * Encodes the distribution point name and writes it to the DerOutputStream.
     *
     * @param out the output stream.
     * @exception IOException on encoding error.
     */
    public void encode(DerOutputStream out) throws IOException {

        DerOutputStream theChoice = new DerOutputStream();

        if (fullName != null) {
            fullName.encode(theChoice);
            out.writeImplicit(
                DerValue.createTag(DerValue.TAG_CONTEXT, true, TAG_FULL_NAME),
                theChoice);

        } else {
            relativeName.encode(theChoice);
            out.writeImplicit(
                DerValue.createTag(DerValue.TAG_CONTEXT, true,
                    TAG_RELATIVE_NAME),
                theChoice);
        }
    }

    /**
     * Compare an object to this distribution point name for equality.
     *
     * @param obj Object to be compared to this
     * @return true if objects match; false otherwise
     */
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof DistributionPointName)) {
            return false;
        }
        DistributionPointName other = (DistributionPointName)obj;

        return equals(this.fullName, other.fullName) &&
               equals(this.relativeName, other.relativeName);
    }

    /**
     * Returns the hash code for this distribution point name.
     *
     * @return the hash code.
     */
    public int hashCode() {
        int hash = hashCode;
        if (hash == 0) {
            hash = 1;
            if (fullName != null) {
                hash += fullName.hashCode();

            } else {
                hash += relativeName.hashCode();
            }
            hashCode = hash;
        }
        return hash;
    }

    /**
     * Returns a printable string of the distribution point name.
     */
    @NonNull
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (fullName != null) {
            sb.append("DistributionPointName:\n     ").append(fullName).append("\n");

        } else {
            sb.append("DistributionPointName:\n     ").append(relativeName).append("\n");
        }

        return sb.toString();
    }

    /*
     * Utility function for a.equals(b) where both a and b may be null.
     */
    private static boolean equals(Object a, Object b) {
        return Objects.equals(a, b);
    }
}