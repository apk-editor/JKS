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

import android.os.Build;

import androidx.annotation.RequiresApi;

import com.apk.jks.pkcs.ContentInfo;
import com.apk.jks.pkcs.PKCS7;
import com.apk.jks.pkcs.SignerInfo;
import com.apk.jks.utils.DerInputStream;
import com.apk.jks.utils.DerOutputStream;
import com.apk.jks.utils.DerValue;
import com.apk.jks.x509.AlgorithmId;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;

public class X509CertPath extends CertPath {

    private static final long serialVersionUID = 4989800333263052980L;

    /**
     * List of certificates in this chain
     */
    private final List<X509Certificate> certs;

    private static final String PKCS7_ENCODING = "PKCS7";
    private static final String PKIPATH_ENCODING = "PkiPath";

    /**
     * List of supported encodings
     */
    private static final Collection<String> encodingList;

    static {
        List<String> list = new ArrayList<>(2);
        list.add(PKIPATH_ENCODING);
        list.add(PKCS7_ENCODING);
        encodingList = Collections.unmodifiableCollection(list);
    }

    /**
     * Creates an <code>X509CertPath</code> from a <code>List</code> of
     * <code>X509Certificate</code>s.
     * <p>
     * The certificates are copied out of the supplied <code>List</code>
     * object.
     *
     * @param certs a <code>List</code> of <code>X509Certificate</code>s
     * @exception CertificateException if <code>certs</code> contains an element
     *                      that is not an <code>X509Certificate</code>
     */
    public X509CertPath(List<? extends Certificate> certs) throws CertificateException {
        super("X.509");

        // Ensure that the List contains only X509Certificates
        for (Object obj : (List<?>)certs) {
            if (!(obj instanceof X509Certificate)) {
                throw new CertificateException
                    ("List is not all X509Certificates: "
                    + obj.getClass().getName());
            }
        }

        // Assumes that the resulting List is thread-safe. This is true
        // because we ensure that it cannot be modified after construction
        // and the methods in the Sun JDK 1.4 implementation of ArrayList that
        // allow read-only access are thread-safe.
        this.certs = Collections.unmodifiableList(
                new ArrayList<>((List<X509Certificate>) certs));
    }

    /**
     * Creates an <code>X509CertPath</code>, reading the encoded form
     * from an <code>InputStream</code>. The data is assumed to be in
     * the default encoding.
     *
     * @param is the <code>InputStream</code> to read the data from
     * @exception CertificateException if an exception occurs while decoding
     */
    public X509CertPath(InputStream is) throws CertificateException {
        this(is, PKIPATH_ENCODING);
    }

    /**
     * Creates an <code>X509CertPath</code>, reading the encoded form
     * from an InputStream. The data is assumed to be in the specified
     * encoding.
     *
     * @param is the <code>InputStream</code> to read the data from
     * @param encoding the encoding used
     * @exception CertificateException if an exception occurs while decoding or
     *   the encoding requested is not supported
     */
    public X509CertPath(InputStream is, String encoding)
            throws CertificateException {
        super("X.509");

        if (PKIPATH_ENCODING.equals(encoding)) {
            certs = parsePKIPATH(is);
        } else if (PKCS7_ENCODING.equals(encoding)) {
            certs = parsePKCS7(is);
        } else {
            throw new CertificateException("unsupported encoding");
        }
    }

    /**
     * Parse a PKIPATH format CertPath from an InputStream. Return an
     * unmodifiable List of the certificates.
     *
     * @param is the <code>InputStream</code> to read the data from
     * @return an unmodifiable List of the certificates
     * @exception CertificateException if an exception occurs
     */
    private static List<X509Certificate> parsePKIPATH(InputStream is)
            throws CertificateException {
        List<X509Certificate> certList;
        CertificateFactory certFac;

        if (is == null) {
            throw new CertificateException("input stream is null");
        }

        try {
            DerInputStream dis = new DerInputStream(readAllBytes(is));
            DerValue[] seq = dis.getSequence(3);
            if (seq.length == 0) {
                return Collections.emptyList();
            }

            certFac = CertificateFactory.getInstance("X.509");
            certList = new ArrayList<>(seq.length);

            // append certs in reverse order (target to trust anchor)
            for (int i = seq.length-1; i >= 0; i--) {
                certList.add((X509Certificate)certFac.generateCertificate
                    (new ByteArrayInputStream(seq[i].toByteArray())));
            }

            return Collections.unmodifiableList(certList);

        } catch (IOException ioe) {
            throw new CertificateException("IOException" +
                    " parsing PkiPath data: " + ioe, ioe);
        }
    }

    /**
     * Parse a PKCS#7 format CertPath from an InputStream. Return an
     * unmodifiable List of the certificates.
     *
     * @param is the <code>InputStream</code> to read the data from
     * @return an unmodifiable List of the certificates
     * @exception CertificateException if an exception occurs
     */
    private static List<X509Certificate> parsePKCS7(InputStream is)
            throws CertificateException {
        List<X509Certificate> certList;

        if (is == null) {
            throw new CertificateException("input stream is null");
        }

        try {
            if (!is.markSupported()) {
                // Copy the entire input stream into an InputStream that does
                // support mark
                is = new ByteArrayInputStream(readAllBytes(is));
            }
            PKCS7 pkcs7 = new PKCS7(is);

            X509Certificate[] certArray = pkcs7.getCertificates();
            // certs are optional in PKCS #7
            if (certArray != null) {
                certList = Arrays.asList(certArray);
            } else {
                // no certs provided
                certList = new ArrayList<>(0);
            }
        } catch (IOException ioe) {
            throw new CertificateException("IOException parsing PKCS7 data: " +
                                        ioe);
        }
        // Assumes that the resulting List is thread-safe. This is true
        // because we ensure that it cannot be modified after construction
        // and the methods in the Sun JDK 1.4 implementation of ArrayList that
        // allow read-only access are thread-safe.
        return Collections.unmodifiableList(certList);
    }

    /*
     * Reads the entire contents of an InputStream into a byte array.
     *
     * @param is the InputStream to read from
     * @return the bytes read from the InputStream
     */
    private static byte[] readAllBytes(InputStream is) throws IOException {
        byte[] buffer = new byte[8192];
        ByteArrayOutputStream baos = new ByteArrayOutputStream(2048);
        int n;
        while ((n = is.read(buffer)) != -1) {
            baos.write(buffer, 0, n);
        }
        return baos.toByteArray();
    }

    /**
     * Returns the encoded form of this certification path, using the
     * default encoding.
     *
     * @return the encoded bytes
     * @exception CertificateEncodingException if an encoding error occurs
     */
    public byte[] getEncoded() throws CertificateEncodingException {
        // @@@ Should cache the encoded form
        return encodePKIPATH();
    }

    /**
     * Encode the CertPath using PKIPATH format.
     *
     * @return a byte array containing the binary encoding of the PkiPath object
     * @exception CertificateEncodingException if an exception occurs
     */
    private byte[] encodePKIPATH() throws CertificateEncodingException {

        ListIterator<X509Certificate> li = certs.listIterator(certs.size());
        try {
            DerOutputStream bytes = new DerOutputStream();
            // encode certs in reverse order (trust anchor to target)
            // according to PkiPath format
            while (li.hasPrevious()) {
                X509Certificate cert = li.previous();
                // check for duplicate cert
                if (certs.lastIndexOf(cert) != certs.indexOf(cert)) {
                    throw new CertificateEncodingException
                        ("Duplicate Certificate");
                }
                // get encoded certificates
                byte[] encoded = cert.getEncoded();
                bytes.write(encoded);
            }

            // Wrap the data in a SEQUENCE
            DerOutputStream derout = new DerOutputStream();
            derout.write(DerValue.tag_SequenceOf, bytes);
            return derout.toByteArray();

        } catch (IOException ioe) {
            throw new CertificateEncodingException
                    ("IOException encoding PkiPath data: " + ioe, ioe);
        }
    }

    /**
     * Encode the CertPath using PKCS#7 format.
     *
     * @return a byte array containing the binary encoding of the PKCS#7 object
     * @exception CertificateEncodingException if an exception occurs
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    private byte[] encodePKCS7() throws CertificateEncodingException {
        PKCS7 p7 = new PKCS7(new AlgorithmId[0],
                             new ContentInfo(ContentInfo.DATA_OID, null),
                             certs.toArray(new X509Certificate[0]),
                             new SignerInfo[0]);
        DerOutputStream derout = new DerOutputStream();
        try {
            p7.encodeSignedData(derout);
        } catch (IOException ioe) {
            throw new CertificateEncodingException(ioe.getMessage());
        }
        return derout.toByteArray();
    }

    /**
     * Returns the encoded form of this certification path, using the
     * specified encoding.
     *
     * @param encoding the name of the encoding to use
     * @return the encoded bytes
     * @exception CertificateEncodingException if an encoding error occurs or
     *   the encoding requested is not supported
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    public byte[] getEncoded(String encoding)
            throws CertificateEncodingException {
        if (PKIPATH_ENCODING.equals(encoding)) {
            return encodePKIPATH();
        } else if (PKCS7_ENCODING.equals(encoding)) {
            return encodePKCS7();
        } else {
            throw new CertificateEncodingException("unsupported encoding");
        }
    }

    /**
     * Returns the encodings supported by this certification path, with the
     * default encoding first.
     *
     * @return an <code>Iterator</code> over the names of the supported
     *         encodings (as Strings)
     */
    public static Iterator<String> getEncodingsStatic() {
        return encodingList.iterator();
    }

    /**
     * Returns an iteration of the encodings supported by this certification
     * path, with the default encoding first.
     * <p>
     * Attempts to modify the returned <code>Iterator</code> via its
     * <code>remove</code> method result in an
     * <code>UnsupportedOperationException</code>.
     *
     * @return an <code>Iterator</code> over the names of the supported
     *         encodings (as Strings)
     */
    public Iterator<String> getEncodings() {
        return getEncodingsStatic();
    }

    /**
     * Returns the list of certificates in this certification path.
     * The <code>List</code> returned must be immutable and thread-safe.
     *
     * @return an immutable <code>List</code> of <code>X509Certificate</code>s
     *         (may be empty, but not null)
     */
    public List<X509Certificate> getCertificates() {
        return certs;
    }

}