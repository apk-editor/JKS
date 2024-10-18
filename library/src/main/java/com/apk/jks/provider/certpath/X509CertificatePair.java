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

package com.apk.jks.provider.certpath;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;

import javax.security.auth.x500.X500Principal;

import com.apk.jks.utils.DerOutputStream;
import com.apk.jks.utils.DerValue;
import com.apk.jks.utils.Cache;
import com.apk.jks.x509.X509CertImpl;
import com.apk.jks.provider.X509Factory;

import androidx.annotation.NonNull;

public class X509CertificatePair {

    /* ASN.1 explicit tags */
    private static final byte TAG_FORWARD = 0;
    private static final byte TAG_REVERSE = 1;

    private X509Certificate forward;
    private X509Certificate reverse;
    private byte[] encoded;

    private static final Cache cache = Cache.newSoftMemoryCache(750);

    /*
     * Create a new X509CertificatePair from its encoding.
     *
     * For internal use only, external code should use generateCertificatePair.
     */
    private X509CertificatePair(byte[] encoded)throws CertificateException {
        try {
            parse(new DerValue(encoded));
            this.encoded = encoded;
        } catch (IOException ex) {
            throw new CertificateException(ex.toString());
        }
        checkPair();
    }

    /**
     * Clear the cache for debugging.
     */
    public static synchronized void clearCache() {
        cache.clear();
    }

    /**
     * Return the DER encoded form of the certificate pair.
     *
     * @return The encoded form of the certificate pair.
     * @throws CertificateEncodingException If an encoding exception occurs.
     */
    public byte[] getEncoded() throws CertificateEncodingException {
        try {
            if (encoded == null) {
                DerOutputStream tmp = new DerOutputStream();
                emit(tmp);
                encoded = tmp.toByteArray();
            }
        } catch (IOException ex) {
            throw new CertificateEncodingException(ex.toString());
        }
        return encoded;
    }

    /**
     * Return a printable representation of the certificate pair.
     *
     * @return A String describing the contents of the pair.
     */
    @NonNull
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("X.509 Certificate Pair: [\n");
        if (forward != null)
            sb.append("  Forward: ").append(forward).append("\n");
        if (reverse != null)
            sb.append("  Reverse: ").append(reverse).append("\n");
        sb.append("]");
        return sb.toString();
    }

    /* Parse the encoded bytes */
    private void parse(DerValue val)
        throws IOException, CertificateException
    {
        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException
                ("Sequence tag missing for X509CertificatePair");
        }

        while (val.data != null && val.data.available() != 0) {
            DerValue opt = val.data.getDerValue();
            short tag = (byte) (opt.tag & 0x01f);
            switch (tag) {
                case TAG_FORWARD:
                    if (opt.isContextSpecific() && opt.isConstructed()) {
                        if (forward != null) {
                            throw new IOException("Duplicate forward "
                                + "certificate in X509CertificatePair");
                        }
                        opt = opt.data.getDerValue();
                        forward = X509Factory.intern
                                        (new X509CertImpl(opt.toByteArray()));
                    }
                    break;
                case TAG_REVERSE:
                    if (opt.isContextSpecific() && opt.isConstructed()) {
                        if (reverse != null) {
                            throw new IOException("Duplicate reverse "
                                + "certificate in X509CertificatePair");
                        }
                        opt = opt.data.getDerValue();
                        reverse = X509Factory.intern
                                        (new X509CertImpl(opt.toByteArray()));
                    }
                    break;
                default:
                    throw new IOException("Invalid encoding of "
                        + "X509CertificatePair");
            }
        }
        if (forward == null && reverse == null) {
            throw new CertificateException("at least one of certificate pair "
                + "must be non-null");
        }
    }

    /* Translate to encoded bytes */
    private void emit(DerOutputStream out)
        throws IOException, CertificateEncodingException
    {
        DerOutputStream tagged = new DerOutputStream();

        if (forward != null) {
            DerOutputStream tmp = new DerOutputStream();
            tmp.putDerValue(new DerValue(forward.getEncoded()));
            tagged.write(DerValue.createTag(DerValue.TAG_CONTEXT,
                         true, TAG_FORWARD), tmp);
        }

        if (reverse != null) {
            DerOutputStream tmp = new DerOutputStream();
            tmp.putDerValue(new DerValue(reverse.getEncoded()));
            tagged.write(DerValue.createTag(DerValue.TAG_CONTEXT,
                         true, TAG_REVERSE), tmp);
        }

        out.write(DerValue.tag_Sequence, tagged);
    }

    /*
     * Check for a valid certificate pair
     */
    private void checkPair() throws CertificateException {

        /* if either of pair is missing, return w/o error */
        if (forward == null || reverse == null) {
            return;
        }
        /*
         * If both elements of the pair are present, check that they
         * are a valid pair.
         */
        X500Principal fwSubject = forward.getSubjectX500Principal();
        X500Principal fwIssuer = forward.getIssuerX500Principal();
        X500Principal rvSubject = reverse.getSubjectX500Principal();
        X500Principal rvIssuer = reverse.getIssuerX500Principal();
        if (!fwIssuer.equals(rvSubject) || !rvIssuer.equals(fwSubject)) {
            throw new CertificateException("subject and issuer names in "
                + "forward and reverse certificates do not match");
        }

        /* check signatures unless key parameters are missing */
        try {
            PublicKey pk = reverse.getPublicKey();
            if (!(pk instanceof DSAPublicKey) ||
                        ((DSAPublicKey)pk).getParams() != null) {
                forward.verify(pk);
            }
            pk = forward.getPublicKey();
            if (!(pk instanceof DSAPublicKey) ||
                        ((DSAPublicKey)pk).getParams() != null) {
                reverse.verify(pk);
            }
        } catch (GeneralSecurityException e) {
            throw new CertificateException("invalid signature: "
                + e.getMessage());
        }
    }
}