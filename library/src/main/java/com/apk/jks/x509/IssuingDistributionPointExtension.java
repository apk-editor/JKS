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

public class IssuingDistributionPointExtension extends Extension
        implements CertAttrSet<String> {

    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT =
                                "x509.info.extensions.IssuingDistributionPoint";

    /**
     * Attribute names.
     */
    public static final String NAME = "IssuingDistributionPoint";
    public static final String POINT = "point";
    public static final String REASONS = "reasons";
    public static final String ONLY_USER_CERTS = "only_user_certs";
    public static final String ONLY_CA_CERTS = "only_ca_certs";
    public static final String ONLY_ATTRIBUTE_CERTS = "only_attribute_certs";
    public static final String INDIRECT_CRL = "indirect_crl";

    /*
     * The distribution point name for the CRL.
     */
    private DistributionPointName distributionPoint = null;

    /*
     * The scope settings for the CRL.
     */
    private ReasonFlags revocationReasons = null;
    private boolean hasOnlyUserCerts = false;
    private boolean hasOnlyCACerts = false;
    private boolean hasOnlyAttributeCerts = false;
    private boolean isIndirectCRL = false;

    /*
     * ASN.1 context specific tag values
     */
    private static final byte TAG_DISTRIBUTION_POINT = 0;
    private static final byte TAG_ONLY_USER_CERTS = 1;
    private static final byte TAG_ONLY_CA_CERTS = 2;
    private static final byte TAG_ONLY_SOME_REASONS = 3;
    private static final byte TAG_INDIRECT_CRL = 4;
    private static final byte TAG_ONLY_ATTRIBUTE_CERTS = 5;

    /**
     * Returns the name of this attribute.
     */
    public String getName() {
        return NAME;
    }

    /**
     * Encodes the issuing distribution point extension and writes it to the
     * DerOutputStream.
     *
     * @param out the output stream.
     * @exception IOException on encoding error.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        if (this.extensionValue == null) {
            this.extensionId = PKIXExtensions.IssuingDistributionPoint_Id;
            this.critical = false;
            encodeThis();
        }
        super.encode(tmp);
        out.write(tmp.toByteArray());
    }

    /**
     * Sets the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        if (name.equalsIgnoreCase(POINT)) {
            if (!(obj instanceof DistributionPointName)) {
                throw new IOException(
                    "Attribute value should be of type DistributionPointName.");
            }
            distributionPoint = (DistributionPointName)obj;

        } else if (name.equalsIgnoreCase(REASONS)) {
            if (!(obj instanceof ReasonFlags)) {
                throw new IOException(
                    "Attribute value should be of type ReasonFlags.");
            }

        } else if (name.equalsIgnoreCase(INDIRECT_CRL)) {
            if (!(obj instanceof Boolean)) {
                throw new IOException(
                    "Attribute value should be of type Boolean.");
            }
            isIndirectCRL = (Boolean) obj;

        } else if (name.equalsIgnoreCase(ONLY_USER_CERTS)) {
            if (!(obj instanceof Boolean)) {
                throw new IOException(
                    "Attribute value should be of type Boolean.");
            }
            hasOnlyUserCerts = (Boolean) obj;

        } else if (name.equalsIgnoreCase(ONLY_CA_CERTS)) {
            if (!(obj instanceof Boolean)) {
                throw new IOException(
                    "Attribute value should be of type Boolean.");
            }
            hasOnlyCACerts = (Boolean) obj;

        } else if (name.equalsIgnoreCase(ONLY_ATTRIBUTE_CERTS)) {
            if (!(obj instanceof Boolean)) {
                throw new IOException(
                    "Attribute value should be of type Boolean.");
            }
            hasOnlyAttributeCerts = (Boolean) obj;


        } else {
            throw new IOException("Attribute name [" + name +
                "] not recognized by " +
                "CertAttrSet:IssuingDistributionPointExtension.");
        }
        encodeThis();
    }

    /**
     * Gets the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(POINT)) {
            return distributionPoint;

        } else if (name.equalsIgnoreCase(INDIRECT_CRL)) {
            return isIndirectCRL;

        } else if (name.equalsIgnoreCase(REASONS)) {
            return revocationReasons;

        } else if (name.equalsIgnoreCase(ONLY_USER_CERTS)) {
            return hasOnlyUserCerts;

        } else if (name.equalsIgnoreCase(ONLY_CA_CERTS)) {
            return hasOnlyCACerts;

        } else if (name.equalsIgnoreCase(ONLY_ATTRIBUTE_CERTS)) {
            return hasOnlyAttributeCerts;

        } else {
            throw new IOException("Attribute name [" + name +
                "] not recognized by " +
                "CertAttrSet:IssuingDistributionPointExtension.");
        }
    }

    /**
     * Deletes the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(POINT)) {
            distributionPoint = null;

        } else if (name.equalsIgnoreCase(INDIRECT_CRL)) {
            isIndirectCRL = false;

        } else if (name.equalsIgnoreCase(REASONS)) {
            revocationReasons = null;

        } else if (name.equalsIgnoreCase(ONLY_USER_CERTS)) {
            hasOnlyUserCerts = false;

        } else if (name.equalsIgnoreCase(ONLY_CA_CERTS)) {
            hasOnlyCACerts = false;

        } else if (name.equalsIgnoreCase(ONLY_ATTRIBUTE_CERTS)) {
            hasOnlyAttributeCerts = false;

        } else {
            throw new IOException("Attribute name [" + name +
                "] not recognized by " +
                "CertAttrSet:IssuingDistributionPointExtension.");
        }
        encodeThis();
    }

    /**
     * Returns an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getElements() {
        AttributeNameEnumeration elements = new AttributeNameEnumeration();
        elements.addElement(POINT);
        elements.addElement(REASONS);
        elements.addElement(ONLY_USER_CERTS);
        elements.addElement(ONLY_CA_CERTS);
        elements.addElement(ONLY_ATTRIBUTE_CERTS);
        elements.addElement(INDIRECT_CRL);
        return elements.elements();
    }

     // Encodes this extension value
    private void encodeThis() throws IOException {

        if (distributionPoint == null &&
            revocationReasons == null &&
            !hasOnlyUserCerts &&
            !hasOnlyCACerts &&
            !hasOnlyAttributeCerts &&
            !isIndirectCRL) {

            this.extensionValue = null;
            return;

        }

        DerOutputStream tagged = new DerOutputStream();

        if (distributionPoint != null) {
            DerOutputStream tmp = new DerOutputStream();
            distributionPoint.encode(tmp);
            tagged.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT, true,
                TAG_DISTRIBUTION_POINT), tmp);
        }

        if (hasOnlyUserCerts) {
            DerOutputStream tmp = new DerOutputStream();
            tmp.putBoolean(hasOnlyUserCerts);
            tagged.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT, false,
                TAG_ONLY_USER_CERTS), tmp);
        }

        if (hasOnlyCACerts) {
            DerOutputStream tmp = new DerOutputStream();
            tmp.putBoolean(hasOnlyCACerts);
            tagged.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT, false,
                TAG_ONLY_CA_CERTS), tmp);
        }

        if (revocationReasons != null) {
            DerOutputStream tmp = new DerOutputStream();
            revocationReasons.encode(tmp);
            tagged.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT, false,
                TAG_ONLY_SOME_REASONS), tmp);
        }

        if (isIndirectCRL) {
            DerOutputStream tmp = new DerOutputStream();
            tmp.putBoolean(isIndirectCRL);
            tagged.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT, false,
                TAG_INDIRECT_CRL), tmp);
        }

        if (hasOnlyAttributeCerts) {
            DerOutputStream tmp = new DerOutputStream();
            tmp.putBoolean(hasOnlyAttributeCerts);
            tagged.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT, false,
                TAG_ONLY_ATTRIBUTE_CERTS), tmp);
        }

        DerOutputStream seq = new DerOutputStream();
        seq.write(DerValue.tag_Sequence, tagged);
        this.extensionValue = seq.toByteArray();
    }

    /**
     * Returns the extension as user readable string.
     */
    @NonNull
    public String toString() {

        StringBuilder sb = new StringBuilder(super.toString());
        sb.append("IssuingDistributionPoint [\n  ");

        if (distributionPoint != null) {
            sb.append(distributionPoint);
        }

        if (revocationReasons != null) {
            sb.append(revocationReasons);
        }

        sb.append((hasOnlyUserCerts)
                ? ("  Only contains user certs: true")
                : ("  Only contains user certs: false")).append("\n");

        sb.append((hasOnlyCACerts)
                ? ("  Only contains CA certs: true")
                : ("  Only contains CA certs: false")).append("\n");

        sb.append((hasOnlyAttributeCerts)
                ? ("  Only contains attribute certs: true")
                : ("  Only contains attribute certs: false")).append("\n");

        sb.append((isIndirectCRL)
                ? ("  Indirect CRL: true")
                : ("  Indirect CRL: false")).append("\n");

        sb.append("]\n");

        return sb.toString();
    }

}