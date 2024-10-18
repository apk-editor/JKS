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
import java.util.Arrays;
import java.util.Objects;

import com.apk.jks.utils.BitArray;
import com.apk.jks.utils.DerOutputStream;
import com.apk.jks.utils.DerValue;

import androidx.annotation.NonNull;

public class DistributionPoint {

    private static final String[] REASON_STRINGS = {
        null,
        "key compromise",
        "CA compromise",
        "affiliation changed",
        "superseded",
        "cessation of operation",
        "certificate hold",
        "privilege withdrawn",
        "AA compromise",
    };

    // context specific tag values
    private static final byte TAG_DIST_PT = 0;
    private static final byte TAG_REASONS = 1;
    private static final byte TAG_ISSUER = 2;

    private static final byte TAG_FULL_NAME = 0;
    private static final byte TAG_REL_NAME = 1;

    // only one of fullName and relativeName can be set
    private GeneralNames fullName;
    private RDN relativeName;

    // reasonFlags or null
    private boolean[] reasonFlags;

    // crlIssuer or null
    private GeneralNames crlIssuer;

    // cached hashCode value
    private volatile int hashCode;

    /**
     * Create the object from the passed DER encoded form.
     *
     * @param val the DER encoded form of the DistributionPoint
     * @throws IOException on error
     */
    public DistributionPoint(DerValue val) throws IOException {
        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding of DistributionPoint.");
        }

        // Note that all the fields in DistributionPoint are defined as
        // being OPTIONAL, i.e., there could be an empty SEQUENCE, resulting
        // in val.data being null.
        while ((val.data != null) && (val.data.available() != 0)) {
            DerValue opt = val.data.getDerValue();

            if (opt.isContextSpecific(TAG_DIST_PT) && opt.isConstructed()) {
                if ((fullName != null) || (relativeName != null)) {
                    throw new IOException("Duplicate DistributionPointName in "
                                          + "DistributionPoint.");
                }
                DerValue distPnt = opt.data.getDerValue();
                if (distPnt.isContextSpecific(TAG_FULL_NAME)
                        && distPnt.isConstructed()) {
                    distPnt.resetTag(DerValue.tag_Sequence);
                    fullName = new GeneralNames(distPnt);
                } else if (distPnt.isContextSpecific(TAG_REL_NAME)
                        && distPnt.isConstructed()) {
                    distPnt.resetTag(DerValue.tag_Set);
                    relativeName = new RDN(distPnt);
                } else {
                    throw new IOException("Invalid DistributionPointName in "
                                          + "DistributionPoint");
                }
            } else if (opt.isContextSpecific(TAG_REASONS)
                                                && !opt.isConstructed()) {
                if (reasonFlags != null) {
                    throw new IOException("Duplicate Reasons in " +
                                          "DistributionPoint.");
                }
                opt.resetTag(DerValue.tag_BitString);
                reasonFlags = (opt.getUnalignedBitString()).toBooleanArray();
            } else if (opt.isContextSpecific(TAG_ISSUER)
                                                && opt.isConstructed()) {
                if (crlIssuer != null) {
                    throw new IOException("Duplicate CRLIssuer in " +
                                          "DistributionPoint.");
                }
                opt.resetTag(DerValue.tag_Sequence);
                crlIssuer = new GeneralNames(opt);
            } else {
                throw new IOException("Invalid encoding of " +
                                      "DistributionPoint.");
            }
        }
        if ((crlIssuer == null) && (fullName == null) && (relativeName == null)) {
            throw new IOException("One of fullName, relativeName, "
                + " and crlIssuer has to be set");
        }
    }

    /**
     * Write the DistributionPoint value to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the extension to.
     * @exception IOException on error.
     */
    public void encode(DerOutputStream out) throws IOException {
        DerOutputStream tagged = new DerOutputStream();

        // NOTE: only one of pointNames and pointRDN can be set
        if ((fullName != null) || (relativeName != null)) {
            DerOutputStream distributionPoint = new DerOutputStream();
            if (fullName != null) {
                DerOutputStream derOut = new DerOutputStream();
                fullName.encode(derOut);
                distributionPoint.writeImplicit(
                    DerValue.createTag(DerValue.TAG_CONTEXT, true, TAG_FULL_NAME),
                    derOut);
            } else if (relativeName != null) {
                DerOutputStream derOut = new DerOutputStream();
                relativeName.encode(derOut);
                distributionPoint.writeImplicit(
                    DerValue.createTag(DerValue.TAG_CONTEXT, true, TAG_REL_NAME),
                    derOut);
            }
            tagged.write(
                DerValue.createTag(DerValue.TAG_CONTEXT, true, TAG_DIST_PT),
                distributionPoint);
        }
        if (reasonFlags != null) {
            DerOutputStream reasons = new DerOutputStream();
            BitArray rf = new BitArray(reasonFlags);
            reasons.putTruncatedUnalignedBitString(rf);
            tagged.writeImplicit(
                DerValue.createTag(DerValue.TAG_CONTEXT, false, TAG_REASONS),
                reasons);
        }
        if (crlIssuer != null) {
            DerOutputStream issuer = new DerOutputStream();
            crlIssuer.encode(issuer);
            tagged.writeImplicit(
                DerValue.createTag(DerValue.TAG_CONTEXT, true, TAG_ISSUER),
                issuer);
        }
        out.write(DerValue.tag_Sequence, tagged);
    }

    /**
     * Utility function for a.equals(b) where both a and b may be null.
     */
    private static boolean equals(Object a, Object b) {
        return Objects.equals(a, b);
    }

    /**
     * Compare an object to this DistributionPoint for equality.
     *
     * @param obj Object to be compared to this
     * @return true if objects match; false otherwise
     */
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof DistributionPoint)) {
            return false;
        }
        DistributionPoint other = (DistributionPoint)obj;

        return equals(this.fullName, other.fullName)
                     && equals(this.relativeName, other.relativeName)
                     && equals(this.crlIssuer, other.crlIssuer)
                     && Arrays.equals(this.reasonFlags, other.reasonFlags);
    }

    public int hashCode() {
        int hash = hashCode;
        if (hash == 0) {
            hash = 1;
            if (fullName != null) {
                hash += fullName.hashCode();
            }
            if (relativeName != null) {
                hash += relativeName.hashCode();
            }
            if (crlIssuer != null) {
                hash += crlIssuer.hashCode();
            }
            if (reasonFlags != null) {
                for (int i = 0; i < reasonFlags.length; i++) {
                    if (reasonFlags[i]) {
                        hash += i;
                    }
                }
            }
            hashCode = hash;
        }
        return hash;
    }

    /**
     * Return a string representation for reasonFlag bit 'reason'.
     */
    private static String reasonToString(int reason) {
        if ((reason > 0) && (reason < REASON_STRINGS.length)) {
            return REASON_STRINGS[reason];
        }
        return "Unknown reason " + reason;
    }

    /**
     * Return a printable string of the Distribution Point.
     */
    @NonNull
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (fullName != null) {
            sb.append("DistributionPoint:\n     ").append(fullName).append("\n");
        }
        if (relativeName != null) {
            sb.append("DistributionPoint:\n     ").append(relativeName).append("\n");
        }

        if (reasonFlags != null) {
            sb.append("   ReasonFlags:\n");
            for (int i = 0; i < reasonFlags.length; i++) {
                if (reasonFlags[i]) {
                    sb.append("    ").append(reasonToString(i)).append("\n");
                }
            }
        }
        if (crlIssuer != null) {
            sb.append("   CRLIssuer:").append(crlIssuer).append("\n");
        }
        return sb.toString();
    }

}