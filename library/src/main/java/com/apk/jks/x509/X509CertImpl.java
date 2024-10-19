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

import com.apk.jks.utils.HexDumpEncoder;
import com.apk.jks.utils.DerValue;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import com.apk.jks.utils.DerEncoder;
import com.apk.jks.utils.DerOutputStream;
import com.apk.jks.utils.ObjectIdentifier;

public class X509CertImpl extends X509Certificate implements DerEncoder {

    private static final long serialVersionUID = -3457612960190864406L;

    private static final String DOT = ".";
    /**
     * Public attribute names.
     */
    public static final String NAME = "x509";
    public static final String INFO = X509CertInfo.NAME;
    public static final String ALG_ID = "algorithm";
    public static final String SIGNATURE = "signature";
    public static final String SIGNED_CERT = "signed_cert";
    public static final String VERSION = NAME + DOT + INFO + DOT +
                               X509CertInfo.VERSION + DOT +
                               CertificateVersion.VERSION;

    // when we sign and decode we set this to true
    // this is our means to make certificates immutable
    private boolean readOnly = false;

    // Certificate data, and its envelope
    private byte[]              signedCert = null;
    protected X509CertInfo info = null;
    protected AlgorithmId algId = null;
    protected byte[]            signature = null;

    // number of standard key usage bits.
    private static final int NUM_STANDARD_KEY_USAGE = 9;

    // SubjectAlterntativeNames cache
    private Collection<List<?>> subjectAlternativeNames;

    // IssuerAlternativeNames cache
    private Collection<List<?>> issuerAlternativeNames;

    // ExtendedKeyUsage cache
    private List<String> extKeyUsage;

    // AuthorityInformationAccess cache

    /**
     * PublicKey that has previously been used to verify
     * the signature of this certificate. Null if the certificate has not
     * yet been verified.
     */
    private PublicKey verifiedPublicKey;
    /**
     * If verifiedPublicKey is not null, name of the provider used to
     * successfully verify the signature of this certificate, or the
     * empty String if no provider was explicitly specified.
     */
    private String verifiedProvider;
    /**
     * If verifiedPublicKey is not null, result of the verification using
     * verifiedPublicKey and verifiedProvider. If true, verification was
     * successful, if false, it failed.
     */
    private boolean verificationResult;

    /**
     * Unmarshals a certificate from its encoded form, parsing the
     * encoded bytes.  This form of constructor is used by agents which
     * need to examine and use certificate contents.  That is, this is
     * one of the more commonly used constructors.  Note that the buffer
     * must include only a certificate, and no "garbage" may be left at
     * the end.  If you need to ignore data at the end of a certificate,
     * use another constructor.
     *
     * @param certData the encoded bytes, with no trailing padding.
     * @exception CertificateException on parsing and initialization errors.
     */
    public X509CertImpl(byte[] certData) throws CertificateException {
        try {
            parse(new DerValue(certData));
        } catch (IOException e) {
            signedCert = null;
            throw new CertificateException("Unable to initialize, " + e);
        }
    }

    /**
     * Unmarshal a certificate from its encoded form, parsing a DER value.
     * This form of constructor is used by agents which need to examine
     * and use certificate contents.
     *
     * @param derVal the der value containing the encoded cert.
     * @exception CertificateException on parsing and initialization errors.
     */
    public X509CertImpl(DerValue derVal) throws CertificateException {
        try {
            parse(derVal);
        } catch (IOException e) {
            signedCert = null;
            throw new
                CertificateException("Unable to initialize, " + e, e);
        }
    }

    /**
     * Appends the certificate to an output stream.
     *
     * @param out an input stream to which the certificate is appended.
     * @exception CertificateEncodingException on encoding errors.
     */
    public void encode(OutputStream out)
    throws CertificateEncodingException {
        if (signedCert == null)
            throw new CertificateEncodingException(
                          "Null certificate to encode");
        try {
            out.write(signedCert.clone());
        } catch (IOException e) {
            throw new CertificateEncodingException(e.toString());
        }
    }

    /**
     * DER encode this object onto an output stream.
     * Implements the <code>DerEncoder</code> interface.
     *
     * @param out the output stream on which to write the DER encoding.
     *
     * @exception IOException on encoding error.
     */
    public void derEncode(OutputStream out) throws IOException {
        if (signedCert == null)
            throw new IOException("Null certificate to encode");
        out.write(signedCert.clone());
    }

    /**
     * Returns the encoded form of this certificate. It is
     * assumed that each certificate type would have only a single
     * form of encoding; for example, X.509 certificates would
     * be encoded as ASN.1 DER.
     *
     * @exception CertificateEncodingException if an encoding error occurs.
     */
    public byte[] getEncoded() throws CertificateEncodingException {
        return getEncodedInternal().clone();
    }

    /**
     * Returned the encoding as an uncloned byte array. Callers must
     * guarantee that they neither modify it nor expose it to untrusted
     * code.
     */
    public byte[] getEncodedInternal() throws CertificateEncodingException {
        if (signedCert == null) {
            throw new CertificateEncodingException(
                          "Null certificate to encode");
        }
        return signedCert;
    }

    /**
     * Throws an exception if the certificate was not signed using the
     * verification key provided.  Successfully verifying a certificate
     * does <em>not</em> indicate that one should trust the entity which
     * it represents.
     *
     * @param key the public key used for verification.
     *
     * @exception InvalidKeyException on incorrect key.
     * @exception NoSuchAlgorithmException on unsupported signature
     * algorithms.
     * @exception NoSuchProviderException if there's no default provider.
     * @exception SignatureException on signature errors.
     * @exception CertificateException on encoding errors.
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    public void verify(PublicKey key)
    throws CertificateException, NoSuchAlgorithmException,
        InvalidKeyException, NoSuchProviderException, SignatureException {

        verify(key, "");
    }

    /**
     * Throws an exception if the certificate was not signed using the
     * verification key provided.  Successfully verifying a certificate
     * does <em>not</em> indicate that one should trust the entity which
     * it represents.
     *
     * @param key the public key used for verification.
     * @param sigProvider the name of the provider.
     *
     * @exception NoSuchAlgorithmException on unsupported signature
     * algorithms.
     * @exception InvalidKeyException on incorrect key.
     * @exception NoSuchProviderException on incorrect provider.
     * @exception SignatureException on signature errors.
     * @exception CertificateException on encoding errors.
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    public synchronized void verify(PublicKey key, String sigProvider)
            throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException {
        if (sigProvider == null) {
            sigProvider = "";
        }
        if ((verifiedPublicKey != null) && verifiedPublicKey.equals(key)) {
            // this certificate has already been verified using
            // this public key. Make sure providers match, too.
            if (sigProvider.equals(verifiedProvider)) {
                if (verificationResult) {
                    return;
                } else {
                    throw new SignatureException("Signature does not match.");
                }
            }
        }
        if (signedCert == null) {
            throw new CertificateEncodingException("Uninitialized certificate");
        }
        // Verify the signature ...
        Signature sigVerf;
        if (sigProvider.isEmpty()) {
            sigVerf = Signature.getInstance(algId.getName());
        } else {
            sigVerf = Signature.getInstance(algId.getName(), sigProvider);
        }
        sigVerf.initVerify(key);

        byte[] rawCert = info.getEncodedInfo();
        sigVerf.update(rawCert, 0, rawCert.length);

        // verify may throw SignatureException for invalid encodings, etc.
        verificationResult = sigVerf.verify(signature);
        verifiedPublicKey = key;
        verifiedProvider = sigProvider;

        if (!verificationResult) {
            throw new SignatureException("Signature does not match.");
        }
    }

    /**
     * Creates an X.509 certificate, and signs it using the given key
     * (associating a signature algorithm and an X.500 name).
     * This operation is used to implement the certificate generation
     * functionality of a certificate authority.
     *
     * @param key the private key used for signing.
     * @param algorithm the name of the signature algorithm used.
     *
     * @exception InvalidKeyException on incorrect key.
     * @exception NoSuchAlgorithmException on unsupported signature
     * algorithms.
     * @exception NoSuchProviderException if there's no default provider.
     * @exception SignatureException on signature errors.
     * @exception CertificateException on encoding errors.
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    public void sign(PrivateKey key, String algorithm)
    throws CertificateException, NoSuchAlgorithmException,
        InvalidKeyException, NoSuchProviderException, SignatureException {
        sign(key, algorithm, null);
    }

    /**
     * Creates an X.509 certificate, and signs it using the given key
     * (associating a signature algorithm and an X.500 name).
     * This operation is used to implement the certificate generation
     * functionality of a certificate authority.
     *
     * @param key the private key used for signing.
     * @param algorithm the name of the signature algorithm used.
     * @param provider the name of the provider.
     *
     * @exception NoSuchAlgorithmException on unsupported signature
     * algorithms.
     * @exception InvalidKeyException on incorrect key.
     * @exception NoSuchProviderException on incorrect provider.
     * @exception SignatureException on signature errors.
     * @exception CertificateException on encoding errors.
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    public void sign(PrivateKey key, String algorithm, String provider)
    throws CertificateException, NoSuchAlgorithmException,
        InvalidKeyException, NoSuchProviderException, SignatureException {
        try {
            if (readOnly)
                throw new CertificateEncodingException(
                              "cannot over-write existing certificate");
            Signature sigEngine;
            if ((provider == null) || (provider.isEmpty()))
                sigEngine = Signature.getInstance(algorithm);
            else
                sigEngine = Signature.getInstance(algorithm, provider);

            sigEngine.initSign(key);

                                // in case the name is reset
            algId = AlgorithmId.get(sigEngine.getAlgorithm());

            DerOutputStream out = new DerOutputStream();
            DerOutputStream tmp = new DerOutputStream();

            // encode certificate info
            info.encode(tmp);
            byte[] rawCert = tmp.toByteArray();

            // encode algorithm identifier
            algId.encode(tmp);

            // Create and encode the signature itself.
            sigEngine.update(rawCert, 0, rawCert.length);
            signature = sigEngine.sign();
            tmp.putBitString(signature);

            // Wrap the signed data in a SEQUENCE { data, algorithm, sig }
            out.write(DerValue.tag_Sequence, tmp);
            signedCert = out.toByteArray();
            readOnly = true;

        } catch (IOException e) {
            throw new CertificateEncodingException(e.toString());
      }
    }

    /**
     * Checks that the certificate is currently valid, i.e. the current
     * time is within the specified validity period.
     *
     * @exception CertificateExpiredException if the certificate has expired.
     * @exception CertificateNotYetValidException if the certificate is not
     * yet valid.
     */
    public void checkValidity()
    throws CertificateExpiredException, CertificateNotYetValidException {
        Date date = new Date();
        checkValidity(date);
    }

    /**
     * Checks that the specified date is within the certificate's
     * validity period, or basically if the certificate would be
     * valid at the specified date/time.
     *
     * @param date the Date to check against to see if this certificate
     *        is valid at that date/time.
     *
     * @exception CertificateExpiredException if the certificate has expired
     * with respect to the <code>date</code> supplied.
     * @exception CertificateNotYetValidException if the certificate is not
     * yet valid with respect to the <code>date</code> supplied.
     */
    public void checkValidity(Date date)
    throws CertificateExpiredException, CertificateNotYetValidException {

        CertificateValidity interval;
        try {
            interval = (CertificateValidity)info.get(CertificateValidity.NAME);
        } catch (Exception e) {
            throw new CertificateNotYetValidException("Incorrect validity period");
        }
        if (interval == null)
            throw new CertificateNotYetValidException("Null validity period");
        interval.valid(date);
    }

    /*
     * Return the requested attribute from the certificate.
     *
     * Note that the X509CertInfo is not cloned for performance reasons.
     * Callers must ensure that they do not modify it. All other
     * attributes are cloned.
     *
     * @param name the name of the attribute.
     * @exception CertificateParsingException on invalid attribute identifier.
     */
    public Object get(String name)
    throws CertificateParsingException {
        X509AttributeName attr = new X509AttributeName(name);
        String id = attr.getPrefix();
        if (!(id.equalsIgnoreCase(NAME))) {
            throw new CertificateParsingException("Invalid root of "
                          + "attribute name, expected [" + NAME +
                          "], received " + "[" + id + "]");
        }
        attr = new X509AttributeName(attr.getSuffix());
        id = attr.getPrefix();

        if (id.equalsIgnoreCase(INFO)) {
            if (info == null) {
                return null;
            }
            if (attr.getSuffix() != null) {
                try {
                    return info.get(attr.getSuffix());
                } catch (IOException | CertificateException e) {
                    throw new CertificateParsingException(e.toString());
                }
            } else {
                return info;
            }
        } else if (id.equalsIgnoreCase(ALG_ID)) {
            return(algId);
        } else if (id.equalsIgnoreCase(SIGNATURE)) {
            if (signature != null)
                return signature.clone();
            else
                return null;
        } else if (id.equalsIgnoreCase(SIGNED_CERT)) {
            if (signedCert != null)
                return signedCert.clone();
            else
                return null;
        } else {
            throw new CertificateParsingException("Attribute name not "
                 + "recognized or get() not allowed for the same: " + id);
        }
    }

    /**
     * Set the requested attribute in the certificate.
     *
     * @param name the name of the attribute.
     * @param obj the value of the attribute.
     * @exception CertificateException on invalid attribute identifier.
     * @exception IOException on encoding error of attribute.
     */
    public void set(String name, Object obj)
    throws CertificateException, IOException {
        // check if immutable
        if (readOnly)
            throw new CertificateException("cannot over-write existing"
                                           + " certificate");

        X509AttributeName attr = new X509AttributeName(name);
        String id = attr.getPrefix();
        if (!(id.equalsIgnoreCase(NAME))) {
            throw new CertificateException("Invalid root of attribute name,"
                           + " expected [" + NAME + "], received " + id);
        }
        attr = new X509AttributeName(attr.getSuffix());
        id = attr.getPrefix();

        if (id.equalsIgnoreCase(INFO)) {
            //reset this as certificate data has changed
            if (attr.getSuffix() == null) {
                if (!(obj instanceof X509CertInfo)) {
                    throw new CertificateException("Attribute value should"
                                    + " be of type X509CertInfo.");
                }
                info = (X509CertInfo)obj;
            } else {
                info.set(attr.getSuffix(), obj);
            }
            signedCert = null;  //reset this as certificate data has changed
        } else {
            throw new CertificateException("Attribute name not recognized or " +
                              "set() not allowed for the same: " + id);
        }
    }

    /**
     * Delete the requested attribute from the certificate.
     *
     * @param name the name of the attribute.
     * @exception CertificateException on invalid attribute identifier.
     * @exception IOException on other errors.
     */
    public void delete(String name)
    throws CertificateException, IOException {
        // check if immutable
        if (readOnly)
            throw new CertificateException("cannot over-write existing"
                                           + " certificate");

        X509AttributeName attr = new X509AttributeName(name);
        String id = attr.getPrefix();
        if (!(id.equalsIgnoreCase(NAME))) {
            throw new CertificateException("Invalid root of attribute name,"
                                   + " expected ["
                                   + NAME + "], received " + id);
        }
        attr = new X509AttributeName(attr.getSuffix());
        id = attr.getPrefix();

        if (id.equalsIgnoreCase(INFO)) {
            if (attr.getSuffix() != null) {
                info = null;
            } else {
                info.delete(attr.getSuffix());
            }
        } else if (id.equalsIgnoreCase(ALG_ID)) {
            algId = null;
        } else if (id.equalsIgnoreCase(SIGNATURE)) {
            signature = null;
        } else if (id.equalsIgnoreCase(SIGNED_CERT)) {
            signedCert = null;
        } else {
            throw new CertificateException("Attribute name not recognized or " +
                              "delete() not allowed for the same: " + id);
        }
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getElements() {
        AttributeNameEnumeration elements = new AttributeNameEnumeration();
        elements.addElement(NAME + DOT + INFO);
        elements.addElement(NAME + DOT + ALG_ID);
        elements.addElement(NAME + DOT + SIGNATURE);
        elements.addElement(NAME + DOT + SIGNED_CERT);

        return elements.elements();
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return(NAME);
    }

    /**
     * Returns a printable representation of the certificate.  This does not
     * contain all the information available to distinguish this from any
     * other certificate.  The certificate must be fully constructed
     * before this function may be called.
     */
    @NonNull
    public String toString() {
        if (info == null || algId == null || signature == null)
            return "";

        HexDumpEncoder encoder = new HexDumpEncoder();

        return "[\n" +
                info.toString() + "\n" +
                "  Algorithm: [" + algId.toString() + "]\n" +
                "  Signature:\n" + encoder.encodeBuffer(signature) +
                "\n]";
    }

    // the strongly typed gets, as per java.security.cert.X509Certificate

    /**
     * Gets the publickey from this certificate.
     *
     * @return the publickey.
     */
    public PublicKey getPublicKey() {
        if (info == null)
            return null;
        try {
            return (PublicKey)info.get(CertificateX509Key.NAME
                                + DOT + CertificateX509Key.KEY);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Gets the version number from the certificate.
     *
     * @return the version number, i.e. 1, 2 or 3.
     */
    public int getVersion() {
        if (info == null)
            return -1;
        try {
            int vers = (Integer) info.get(CertificateVersion.NAME
                    + DOT + CertificateVersion.VERSION);
            return vers+1;
        } catch (Exception e) {
            return -1;
        }
    }

    /**
     * Gets the serial number from the certificate.
     *
     * @return the serial number.
     */
    public BigInteger getSerialNumber() {
        SerialNumber ser = getSerialNumberObject();

        return ser != null ? ser.getNumber() : null;
    }

    /**
     * Gets the serial number from the certificate as
     * a SerialNumber object.
     *
     * @return the serial number.
     */
    public SerialNumber getSerialNumberObject() {
        if (info == null)
            return null;
        try {
           return (SerialNumber)info.get(
                   CertificateSerialNumber.NAME + DOT +
                           CertificateSerialNumber.NUMBER);
        } catch (Exception e) {
            return null;
        }
    }


    /**
     * Gets the subject distinguished name from the certificate.
     *
     * @return the subject name.
     */
    public Principal getSubjectDN() {
        if (info == null)
            return null;
        try {
            return (Principal)info.get(
                    CertificateSubjectName.NAME + DOT +
                            CertificateSubjectName.DN_NAME);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Get subject name as X500Principal. Overrides implementation in
     * X509Certificate with a slightly more efficient version that is
     * also aware of X509CertImpl mutability.
     */
    public X500Principal getSubjectX500Principal() {
        if (info == null) {
            return null;
        }
        try {
            return (X500Principal)info.get(
                                CertificateSubjectName.NAME + DOT +
                                CertificateSubjectName.DN_PRINCIPAL);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Gets the issuer distinguished name from the certificate.
     *
     * @return the issuer name.
     */
    public Principal getIssuerDN() {
        if (info == null)
            return null;
        try {
            return (Principal)info.get(
                                CertificateIssuerName.NAME + DOT +
                                CertificateIssuerName.DN_NAME);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Get issuer name as X500Principal. Overrides implementation in
     * X509Certificate with a slightly more efficient version that is
     * also aware of X509CertImpl mutability.
     */
    public X500Principal getIssuerX500Principal() {
        if (info == null) {
            return null;
        }
        try {
            return (X500Principal)info.get(
                                CertificateIssuerName.NAME + DOT +
                                CertificateIssuerName.DN_PRINCIPAL);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Gets the notBefore date from the validity period of the certificate.
     *
     * @return the start date of the validity period.
     */
    public Date getNotBefore() {
        if (info == null)
            return null;
        try {
            return (Date) info.get(CertificateValidity.NAME + DOT +
                                        CertificateValidity.NOT_BEFORE);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Gets the notAfter date from the validity period of the certificate.
     *
     * @return the end date of the validity period.
     */
    public Date getNotAfter() {
        if (info == null)
            return null;
        try {
            return (Date) info.get(CertificateValidity.NAME + DOT +
                                     CertificateValidity.NOT_AFTER);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Gets the DER encoded certificate informations, the
     * <code>tbsCertificate</code> from this certificate.
     * This can be used to verify the signature independently.
     *
     * @return the DER encoded certificate information.
     * @exception CertificateEncodingException if an encoding error occurs.
     */
    public byte[] getTBSCertificate() throws CertificateEncodingException {
        if (info != null) {
            return info.getEncodedInfo();
        } else
            throw new CertificateEncodingException("Uninitialized certificate");
    }

    /**
     * Gets the raw Signature bits from the certificate.
     *
     * @return the signature.
     */
    public byte[] getSignature() {
        if (signature == null)
            return null;
        byte[] dup = new byte[signature.length];
        System.arraycopy(signature, 0, dup, 0, dup.length);
        return dup;
    }

    /**
     * Gets the signature algorithm name for the certificate
     * signature algorithm.
     * For example, the string "SHA-1/DSA" or "DSS".
     *
     * @return the signature algorithm name.
     */
    public String getSigAlgName() {
        if (algId == null)
            return null;
        return (algId.getName());
    }

    /**
     * Gets the signature algorithm OID string from the certificate.
     * For example, the string "1.2.840.10040.4.3"
     *
     * @return the signature algorithm oid string.
     */
    public String getSigAlgOID() {
        if (algId == null)
            return null;
        ObjectIdentifier oid = algId.getOID();
        return (oid.toString());
    }

    /**
     * Gets the DER encoded signature algorithm parameters from this
     * certificate's signature algorithm.
     *
     * @return the DER encoded signature algorithm parameters, or
     *         null if no parameters are present.
     */
    public byte[] getSigAlgParams() {
        if (algId == null)
            return null;
        try {
            return algId.getEncodedParams();
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Gets the Issuer Unique Identity from the certificate.
     *
     * @return the Issuer Unique Identity.
     */
    public boolean[] getIssuerUniqueID() {
        if (info == null)
            return null;
        try {
            UniqueIdentity id = (UniqueIdentity)info.get(
                                 CertificateIssuerUniqueIdentity.NAME
                            + DOT + CertificateIssuerUniqueIdentity.ID);
            if (id == null)
                return null;
            else
                return (id.getId());
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Gets the Subject Unique Identity from the certificate.
     *
     * @return the Subject Unique Identity.
     */
    public boolean[] getSubjectUniqueID() {
        if (info == null)
            return null;
        try {
            UniqueIdentity id = (UniqueIdentity)info.get(
                                 CertificateSubjectUniqueIdentity.NAME
                            + DOT + CertificateSubjectUniqueIdentity.ID);
            if (id == null)
                return null;
            else
                return (id.getId());
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Get ExtendedKeyUsage extension
     * @return ExtendedKeyUsage extension object or null (if no such object
     * in certificate)
     */
    public ExtendedKeyUsageExtension getExtendedKeyUsageExtension() {
        return (ExtendedKeyUsageExtension)
            getExtension(PKIXExtensions.ExtendedKeyUsage_Id);
    }

    /**
     * Get IssuerAlternativeName extension
     * @return IssuerAlternativeName object or null (if no such object in
     * certificate)
     */
    public IssuerAlternativeNameExtension getIssuerAlternativeNameExtension() {
        return (IssuerAlternativeNameExtension)
            getExtension(PKIXExtensions.IssuerAlternativeName_Id);
    }

    /**
     * Get SubjectAlternativeName extension
     * @return SubjectAlternativeName object or null (if no such object in
     * certificate)
     */
    public SubjectAlternativeNameExtension getSubjectAlternativeNameExtension()
    {
        return (SubjectAlternativeNameExtension)
            getExtension(PKIXExtensions.SubjectAlternativeName_Id);
    }

    /**
     * Return true if a critical extension is found that is
     * not supported, otherwise return false.
     */
    public boolean hasUnsupportedCriticalExtension() {
        if (info == null)
            return false;
        try {
            CertificateExtensions exts = (CertificateExtensions)info.get(
                                         CertificateExtensions.NAME);
            if (exts == null)
                return false;
            return exts.hasUnsupportedCriticalExtension();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Gets a Set of the extension(s) marked CRITICAL in the
     * certificate. In the returned set, each extension is
     * represented by its OID string.
     *
     * @return a set of the extension oid strings in the
     * certificate that are marked critical.
     */
    public Set<String> getCriticalExtensionOIDs() {
        if (info == null) {
            return null;
        }
        try {
            CertificateExtensions exts = (CertificateExtensions)info.get(
                                         CertificateExtensions.NAME);
            if (exts == null) {
                return null;
            }
            Set<String> extSet = new HashSet<>();
            for (Extension ex : exts.getAllExtensions()) {
                if (ex.isCritical()) {
                    extSet.add(ex.getExtensionId().toString());
                }
            }
            return extSet;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Gets a Set of the extension(s) marked NON-CRITICAL in the
     * certificate. In the returned set, each extension is
     * represented by its OID string.
     *
     * @return a set of the extension oid strings in the
     * certificate that are NOT marked critical.
     */
    public Set<String> getNonCriticalExtensionOIDs() {
        if (info == null) {
            return null;
        }
        try {
            CertificateExtensions exts = (CertificateExtensions)info.get(
                                         CertificateExtensions.NAME);
            if (exts == null) {
                return null;
            }
            Set<String> extSet = new HashSet<>();
            for (Extension ex : exts.getAllExtensions()) {
                if (!ex.isCritical()) {
                    extSet.add(ex.getExtensionId().toString());
                }
            }
            extSet.addAll(exts.getUnparseableExtensions().keySet());
            return extSet;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Gets the extension identified by the given ObjectIdentifier
     *
     * @param oid the Object Identifier value for the extension.
     * @return Extension or null if certificate does not contain this
     *         extension
     */
    public Extension getExtension(ObjectIdentifier oid) {
        if (info == null) {
            return null;
        }
        try {
            CertificateExtensions extensions;
            try {
                extensions = (CertificateExtensions)info.get(CertificateExtensions.NAME);
            } catch (CertificateException ce) {
                return null;
            }
            if (extensions != null) {
                for (Extension ex : extensions.getAllExtensions()) {
                    if (ex.getExtensionId().equals(oid)) {
                        //XXXX May want to consider cloning this
                        return ex;
                    }
                }
                /* no such extension in this certificate */
            }
            return null;
        } catch (IOException ioe) {
            return null;
        }
    }

    /**
     * Gets the DER encoded extension identified by the given
     * oid String.
     *
     * @param oid the Object Identifier value for the extension.
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    public byte[] getExtensionValue(String oid) {
        try {
            ObjectIdentifier findOID = new ObjectIdentifier(oid);
            String extAlias = OIDMap.getName(findOID);
            Extension certExt = null;
            CertificateExtensions exts = (CertificateExtensions)info.get(
                                     CertificateExtensions.NAME);

            if (extAlias == null) { // may be unknown
                // get the extensions, search thru' for this oid
                if (exts == null) {
                    return null;
                }

                for (Extension ex : exts.getAllExtensions()) {
                    ObjectIdentifier inCertOID = ex.getExtensionId();
                    if (inCertOID.equals(findOID)) {
                        certExt = ex;
                        break;
                    }
                }
            } else { // there's sub-class that can handle this extension
                try {
                    certExt = (Extension)this.get(extAlias);
                } catch (CertificateException e) {
                    // get() throws an Exception instead of returning null, ignore
                }
            }
            if (certExt == null) {
                if (exts != null) {
                    certExt = exts.getUnparseableExtensions().get(oid);
                }
                if (certExt == null) {
                    return null;
                }
            }
            byte[] extData = certExt.getExtensionValue();
            if (extData == null) {
                return null;
            }
            DerOutputStream out = new DerOutputStream();
            out.putOctetString(extData);
            return out.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Get a boolean array representing the bits of the KeyUsage extension,
     * (oid = 2.5.29.15).
     * @return the bit values of this extension as an array of booleans.
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    public boolean[] getKeyUsage() {
        try {
            String extAlias = OIDMap.getName(PKIXExtensions.KeyUsage_Id);
            if (extAlias == null)
                return null;

            KeyUsageExtension certExt = (KeyUsageExtension)this.get(extAlias);
            if (certExt == null)
                return null;

            boolean[] ret = certExt.getBits();
            if (ret.length < NUM_STANDARD_KEY_USAGE) {
                boolean[] usageBits = new boolean[NUM_STANDARD_KEY_USAGE];
                System.arraycopy(ret, 0, usageBits, 0, ret.length);
                ret = usageBits;
            }
            return ret;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * This method are the overridden implementation of
     * getExtendedKeyUsage method in X509Certificate in the Sun
     * provider. It is better performance-wise since it returns cached
     * values.
     */
    public synchronized List<String> getExtendedKeyUsage() {
        if (!readOnly || extKeyUsage == null) {
            ExtendedKeyUsageExtension ext = getExtendedKeyUsageExtension();
            if (ext == null) {
                return null;
            }
            extKeyUsage =
                    Collections.unmodifiableList(ext.getExtendedKeyUsage());
        }
        return extKeyUsage;
    }

    /**
     * Get the certificate constraints path length from the
     * the critical BasicConstraints extension, (oid = 2.5.29.19).
     * @return the length of the constraint.
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    public int getBasicConstraints() {
        try {
            String extAlias = OIDMap.getName(PKIXExtensions.BasicConstraints_Id);
            if (extAlias == null)
                return -1;
            BasicConstraintsExtension certExt =
                        (BasicConstraintsExtension)this.get(extAlias);
            if (certExt == null)
                return -1;

            if ((Boolean) certExt.get(BasicConstraintsExtension.IS_CA))
                return (Integer) certExt.get(
                        BasicConstraintsExtension.PATH_LEN);
            else
                return -1;
        } catch (Exception e) {
            return -1;
        }
    }

    /**
     * Converts a GeneralNames structure into an immutable Collection of
     * alternative names (subject or issuer) in the form required by
     * {@link #getSubjectAlternativeNames} or
     * {@link #getIssuerAlternativeNames}.
     *
     * @param names the GeneralNames to be converted
     * @return an immutable Collection of alternative names
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private static Collection<List<?>> makeAltNames(GeneralNames names) {
        if (names.isEmpty()) {
            return Collections.emptySet();
        }
        Set<List<?>> newNames = new HashSet<>();
        for (GeneralName gname : names.names()) {
            GeneralNameInterface name = gname.getName();
            List<Object> nameEntry = new ArrayList<>(2);
            nameEntry.add(name.getType());
            switch (name.getType()) {
            case GeneralNameInterface.NAME_RFC822:
                nameEntry.add(((RFC822Name) name).getName());
                break;
            case GeneralNameInterface.NAME_DNS:
                nameEntry.add(((DNSName) name).getName());
                break;
            case GeneralNameInterface.NAME_DIRECTORY:
                nameEntry.add(((X500Name) name).getRFC2253Name());
                break;
            case GeneralNameInterface.NAME_URI:
                nameEntry.add(((URIName) name).getName());
                break;
            case GeneralNameInterface.NAME_IP:
                try {
                    nameEntry.add(((IPAddressName) name).getName());
                } catch (IOException ioe) {
                    // IPAddressName in cert is bogus
                    throw new RuntimeException("IPAddress cannot be parsed",
                        ioe);
                }
                break;
            case GeneralNameInterface.NAME_OID:
                nameEntry.add(((OIDName) name).getOID().toString());
                break;
            default:
                // add DER encoded form
                DerOutputStream derOut = new DerOutputStream();
                try {
                    name.encode(derOut);
                } catch (IOException ioe) {
                    // should not occur since name has already been decoded
                    // from cert (this would indicate a bug in our code)
                    throw new RuntimeException("name cannot be encoded", ioe);
                }
                nameEntry.add(derOut.toByteArray());
                break;
            }
            newNames.add(Collections.unmodifiableList(nameEntry));
        }
        return Collections.unmodifiableCollection(newNames);
    }

    /**
     * Checks a Collection of altNames and clones any name entries of type
     * byte [].
     */ // only partially generified due to javac bug
    private static Collection<List<?>> cloneAltNames(Collection<List<?>> altNames) {
        boolean mustClone = false;
        for (List<?> nameEntry : altNames) {
            if (nameEntry.get(1) instanceof byte[]) {
                // must clone names
                mustClone = true;
                break;
            }
        }
        if (mustClone) {
            Set<List<?>> namesCopy = new HashSet<>();
            for (List<?> nameEntry : altNames) {
                Object nameObject = nameEntry.get(1);
                if (nameObject instanceof byte[]) {
                    List<Object> nameEntryCopy =
                            new ArrayList<>(nameEntry);
                    nameEntryCopy.set(1, ((byte[])nameObject).clone());
                    namesCopy.add(Collections.unmodifiableList(nameEntryCopy));
                } else {
                    namesCopy.add(nameEntry);
                }
            }
            return Collections.unmodifiableCollection(namesCopy);
        } else {
            return altNames;
        }
    }

    /**
     * This method are the overridden implementation of
     * getSubjectAlternativeNames method in X509Certificate in the Sun
     * provider. It is better performance-wise since it returns cached
     * values.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public synchronized Collection<List<?>> getSubjectAlternativeNames() {
        // return cached value if we can
        if (readOnly && subjectAlternativeNames != null)  {
            return cloneAltNames(subjectAlternativeNames);
        }
        SubjectAlternativeNameExtension subjectAltNameExt =
            getSubjectAlternativeNameExtension();
        if (subjectAltNameExt == null) {
            return null;
        }
        GeneralNames names;
        try {
            names = (GeneralNames) subjectAltNameExt.get
                (SubjectAlternativeNameExtension.SUBJECT_NAME);
        } catch (IOException ioe) {
            // should not occur
            return Collections.emptySet();
        }
        subjectAlternativeNames = makeAltNames(names);
        return subjectAlternativeNames;
    }

    /**
     * This method are the overridden implementation of
     * getIssuerAlternativeNames method in X509Certificate in the Sun
     * provider. It is better performance-wise since it returns cached
     * values.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public synchronized Collection<List<?>> getIssuerAlternativeNames() {
        // return cached value if we can
        if (readOnly && issuerAlternativeNames != null) {
            return cloneAltNames(issuerAlternativeNames);
        }
        IssuerAlternativeNameExtension issuerAltNameExt =
            getIssuerAlternativeNameExtension();
        if (issuerAltNameExt == null) {
            return null;
        }
        GeneralNames names;
        try {
            names = (GeneralNames) issuerAltNameExt.get
                (IssuerAlternativeNameExtension.ISSUER_NAME);
        } catch (IOException ioe) {
            // should not occur
            return Collections.emptySet();
        }
        issuerAlternativeNames = makeAltNames(names);
        return issuerAlternativeNames;
    }

    /************************************************************/

    /*
     * Cert is a SIGNED ASN.1 macro, a three elment sequence:
     *
     *  - Data to be signed (ToBeSigned) -- the "raw" cert
     *  - Signature algorithm (SigAlgId)
     *  - The signature bits
     *
     * This routine unmarshals the certificate, saving the signature
     * parts away for later verification.
     */
    private void parse(DerValue val)
    throws CertificateException, IOException {
        // check if can over write the certificate
        if (readOnly)
            throw new CertificateParsingException(
                      "cannot over-write existing certificate");

        if (val.data == null || val.tag != DerValue.tag_Sequence)
            throw new CertificateParsingException(
                      "invalid DER-encoded certificate data");

        signedCert = val.toByteArray();
        DerValue[] seq = new DerValue[3];

        seq[0] = val.data.getDerValue();
        seq[1] = val.data.getDerValue();
        seq[2] = val.data.getDerValue();

        if (val.data.available() != 0) {
            throw new CertificateParsingException("signed overrun, bytes = "
                                     + val.data.available());
        }
        if (seq[0].tag != DerValue.tag_Sequence) {
            throw new CertificateParsingException("signed fields invalid");
        }

        algId = AlgorithmId.parse(seq[1]);
        signature = seq[2].getBitString();

        if (seq[1].data.available() != 0) {
            throw new CertificateParsingException("algid field overrun");
        }
        if (seq[2].data.available() != 0)
            throw new CertificateParsingException("signed fields overrun");

        // The CertificateInfo
        info = new X509CertInfo(seq[0]);

        // the "inner" and "outer" signature algorithms must match
        AlgorithmId infoSigAlg = (AlgorithmId)info.get(
                                              CertificateAlgorithmId.NAME
                                              + DOT +
                                              CertificateAlgorithmId.ALGORITHM);
        if (! algId.equals(infoSigAlg))
            throw new CertificateException("Signature algorithm mismatch");
        readOnly = true;
    }

}