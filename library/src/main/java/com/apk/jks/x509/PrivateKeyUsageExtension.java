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

import com.apk.jks.utils.DerValue;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Date;
import java.util.Enumeration;

import com.apk.jks.utils.DerInputStream;
import com.apk.jks.utils.DerOutputStream;

public class PrivateKeyUsageExtension extends Extension implements CertAttrSet<String> {
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.extensions.PrivateKeyUsage";
    /**
     * Sub attributes name for this CertAttrSet.
     */
    public static final String NAME = "PrivateKeyUsage";
    public static final String NOT_BEFORE = "not_before";
    public static final String NOT_AFTER = "not_after";

    // Private data members
    private static final byte TAG_BEFORE = 0;
    private static final byte TAG_AFTER = 1;

    private Date        notBefore = null;
    private Date        notAfter = null;

    // Encode this extension value.
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private void encodeThis() throws IOException {
        if (notBefore == null && notAfter == null) {
            this.extensionValue = null;
            return;
        }
        DerOutputStream seq = new DerOutputStream();

        DerOutputStream tagged = new DerOutputStream();
        if (notBefore != null) {
            DerOutputStream tmp = new DerOutputStream();
            tmp.putGeneralizedTime(notBefore);
            tagged.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                                 false, TAG_BEFORE), tmp);
        }
        if (notAfter != null) {
            DerOutputStream tmp = new DerOutputStream();
            tmp.putGeneralizedTime(notAfter);
            tagged.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                                 false, TAG_AFTER), tmp);
        }
        seq.write(DerValue.tag_Sequence, tagged);
        this.extensionValue = seq.toByteArray();
    }

    /**
     * Create the extension from the passed DER encoded value.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param value an array of DER encoded bytes of the actual value.
     * @exception ClassCastException if value is not an array of bytes
     * @exception CertificateException on certificate parsing errors.
     * @exception IOException on error.
     */
    public PrivateKeyUsageExtension(Boolean critical, Object value)
    throws CertificateException, IOException {
        this.extensionId = PKIXExtensions.PrivateKeyUsage_Id;
        this.critical = critical;

        this.extensionValue = (byte[]) value;
        DerInputStream str = new DerInputStream(this.extensionValue);
        DerValue[] seq = str.getSequence(2);

        // NB. this is always encoded with the IMPLICIT tag
        // The checks only make sense if we assume implicit tagging,
        // with explicit tagging the form is always constructed.
        for (DerValue opt : seq) {
            if (opt.isContextSpecific(TAG_BEFORE) &&
                    !opt.isConstructed()) {
                if (notBefore != null) {
                    throw new CertificateParsingException(
                            "Duplicate notBefore in PrivateKeyUsage.");
                }
                opt.resetTag(DerValue.tag_GeneralizedTime);
                str = new DerInputStream(opt.toByteArray());
                notBefore = str.getGeneralizedTime();

            } else if (opt.isContextSpecific(TAG_AFTER) &&
                    !opt.isConstructed()) {
                if (notAfter != null) {
                    throw new CertificateParsingException(
                            "Duplicate notAfter in PrivateKeyUsage.");
                }
                opt.resetTag(DerValue.tag_GeneralizedTime);
                str = new DerInputStream(opt.toByteArray());
                notAfter = str.getGeneralizedTime();
            } else
                throw new IOException("Invalid encoding of " +
                        "PrivateKeyUsageExtension");
        }
    }

    /**
     * Return the printable string.
     */
    @NonNull
    public String toString() {
        return(super.toString() +
                "PrivateKeyUsage: [\n" +
                ((notBefore == null) ? "" : "From: " + notBefore + ", ")
                + ((notAfter == null) ? "" : "To: " + notAfter)
                + "]\n");
    }

    /**
     * Verify that that the current time is within the validity period.
     *
     * @exception CertificateExpiredException if the certificate has expired.
     * @exception CertificateNotYetValidException if the certificate is not
     * yet valid.
     */
    public void valid()
    throws CertificateNotYetValidException, CertificateExpiredException {
        Date now = new Date();
        valid(now);
    }

    /**
     * Verify that that the passed time is within the validity period.
     *
     * @exception CertificateExpiredException if the certificate has expired
     * with respect to the <code>Date</code> supplied.
     * @exception CertificateNotYetValidException if the certificate is not
     * yet valid with respect to the <code>Date</code> supplied.
     *
     */
    public void valid(Date now)
    throws CertificateNotYetValidException, CertificateExpiredException {
        /*
         * we use the internal Dates rather than the passed in Date
         * because someone could override the Date methods after()
         * and before() to do something entirely different.
         */
        if (notBefore.after(now)) {
            throw new CertificateNotYetValidException("NotBefore: " +
                    notBefore);
        }
        if (notAfter.before(now)) {
            throw new CertificateExpiredException("NotAfter: " +
                    notAfter);
        }
    }

    /**
     * Write the extension to the OutputStream.
     *
     * @param out the OutputStream to write the extension to.
     * @exception IOException on encoding errors.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        if (extensionValue == null) {
            extensionId = PKIXExtensions.PrivateKeyUsage_Id;
            critical = false;
            encodeThis();
        }
        super.encode(tmp);
        out.write(tmp.toByteArray());
    }

    /**
     * Set the attribute value.
     * @exception CertificateException on attribute handling errors.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public void set(String name, Object obj)
    throws CertificateException, IOException {
        if (!(obj instanceof Date)) {
            throw new CertificateException("Attribute must be of type Date.");
        }
        if (name.equalsIgnoreCase(NOT_BEFORE)) {
            notBefore = (Date)obj;
        } else if (name.equalsIgnoreCase(NOT_AFTER)) {
            notAfter = (Date)obj;
        } else {
          throw new CertificateException("Attribute name not recognized by"
                           + " CertAttrSet:PrivateKeyUsage.");
        }
        encodeThis();
    }

    /**
     * Get the attribute value.
     * @exception CertificateException on attribute handling errors.
     */
    public Object get(String name) throws CertificateException {
      if (name.equalsIgnoreCase(NOT_BEFORE)) {
          return (new Date(notBefore.getTime()));
      } else if (name.equalsIgnoreCase(NOT_AFTER)) {
          return (new Date(notAfter.getTime()));
      } else {
          throw new CertificateException("Attribute name not recognized by"
                           + " CertAttrSet:PrivateKeyUsage.");
      }
  }

    /**
     * Delete the attribute value.
     * @exception CertificateException on attribute handling errors.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public void delete(String name) throws CertificateException, IOException {
        if (name.equalsIgnoreCase(NOT_BEFORE)) {
            notBefore = null;
        } else if (name.equalsIgnoreCase(NOT_AFTER)) {
            notAfter = null;
        } else {
          throw new CertificateException("Attribute name not recognized by"
                           + " CertAttrSet:PrivateKeyUsage.");
        }
        encodeThis();
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getElements() {
        AttributeNameEnumeration elements = new AttributeNameEnumeration();
        elements.addElement(NOT_BEFORE);
        elements.addElement(NOT_AFTER);

        return(elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
      return(NAME);
    }
}