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
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import com.apk.jks.utils.DerEncoder;
import com.apk.jks.utils.DerInputStream;
import com.apk.jks.utils.DerOutputStream;
import com.apk.jks.utils.ObjectIdentifier;

public class X509CRLImpl extends X509CRL implements DerEncoder {

    // CRL data, and its envelope
    private byte[]      signedCRL = null; // DER encoded crl
    private byte[]      signature = null; // raw signature bits
    private byte[]      tbsCertList = null; // DER encoded "to-be-signed" CRL
    private AlgorithmId sigAlgId = null; // sig alg in CRL

    // crl information
    private int              version;
    private AlgorithmId infoSigAlgId; // sig alg in "to-be-signed" crl
    private X500Name issuer = null;
    private X500Principal    issuerPrincipal = null;
    private Date             thisUpdate = null;
    private Date             nextUpdate = null;
    private final Map<X509IssuerSerial,X509CRLEntry> revokedCerts = new LinkedHashMap<>();
    private CRLExtensions extensions = null;
    private final static boolean isExplicit = true;
    private static final long YR_2050 = 2524636800000L;

    private boolean readOnly = false;

    /**
     * PublicKey that has previously been used to successfully verify
     * the signature of this CRL. Null if the CRL has not
     * yet been verified (successfully).
     */
    private PublicKey verifiedPublicKey;
    /**
     * If verifiedPublicKey is not null, name of the provider used to
     * successfully verify the signature of this CRL, or the
     * empty String if no provider was explicitly specified.
     */
    private String verifiedProvider;

    /**
     * Unmarshals an X.509 CRL from its encoded form, parsing the encoded
     * bytes.  This form of constructor is used by agents which
     * need to examine and use CRL contents. Note that the buffer
     * must include only one CRL, and no "garbage" may be left at
     * the end.
     *
     * @param crlData the encoded bytes, with no trailing padding.
     * @exception CRLException on parsing errors.
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    public X509CRLImpl(byte[] crlData) throws CRLException {
        try {
            parse(new DerValue(crlData));
        } catch (IOException e) {
            signedCRL = null;
            throw new CRLException("Parsing error: " + e.getMessage());
        }
    }

    /**
     * Unmarshals an X.509 CRL from an DER value.
     *
     * @param val a DER value holding at least one CRL
     * @exception CRLException on parsing errors.
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    public X509CRLImpl(DerValue val) throws CRLException {
        try {
            parse(val);
        } catch (IOException e) {
            signedCRL = null;
            throw new CRLException("Parsing error: " + e.getMessage());
        }
    }

    /**
     * Returned the encoding as an uncloned byte array. Callers must
     * guarantee that they neither modify it nor expose it to untrusted
     * code.
     */
    public byte[] getEncodedInternal() throws CRLException {
        if (signedCRL == null) {
            throw new CRLException("Null CRL to encode");
        }
        return signedCRL;
    }

    /**
     * Returns the ASN.1 DER encoded form of this CRL.
     *
     * @exception CRLException if an encoding error occurs.
     */
    public byte[] getEncoded() throws CRLException {
        return getEncodedInternal().clone();
    }

    /**
     * Encodes the "to-be-signed" CRL to the OutputStream.
     *
     * @param out the OutputStream to write to.
     * @exception CRLException on encoding errors.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public void encodeInfo(OutputStream out) throws CRLException {
        try {
            DerOutputStream tmp = new DerOutputStream();
            DerOutputStream rCerts = new DerOutputStream();
            DerOutputStream seq = new DerOutputStream();

            if (version != 0) // v2 crl encode version
                tmp.putInteger(version);
            infoSigAlgId.encode(tmp);
            if ((version == 0)) {
                issuer.toString();
            }
            issuer.encode(tmp);

            if (thisUpdate.getTime() < YR_2050)
                tmp.putUTCTime(thisUpdate);
            else
                tmp.putGeneralizedTime(thisUpdate);

            if (nextUpdate != null) {
                if (nextUpdate.getTime() < YR_2050)
                    tmp.putUTCTime(nextUpdate);
                else
                    tmp.putGeneralizedTime(nextUpdate);
            }

            if (!revokedCerts.isEmpty()) {
                for (X509CRLEntry entry : revokedCerts.values()) {
                    ((X509CRLEntryImpl)entry).encode(rCerts);
                }
                tmp.write(DerValue.tag_Sequence, rCerts);
            }

            if (extensions != null)
                extensions.encode(tmp, isExplicit);

            seq.write(DerValue.tag_Sequence, tmp);

            tbsCertList = seq.toByteArray();
            out.write(tbsCertList);
        } catch (IOException e) {
             throw new CRLException("Encoding error: " + e.getMessage());
        }
    }

    /**
     * Verifies that this CRL was signed using the
     * private key that corresponds to the given public key.
     *
     * @param key the PublicKey used to carry out the verification.
     *
     * @exception NoSuchAlgorithmException on unsupported signature
     * algorithms.
     * @exception InvalidKeyException on incorrect key.
     * @exception NoSuchProviderException if there's no default provider.
     * @exception SignatureException on signature errors.
     * @exception CRLException on encoding errors.
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    public void verify(PublicKey key)
    throws CRLException, NoSuchAlgorithmException, InvalidKeyException,
           NoSuchProviderException, SignatureException {
        verify(key, "");
    }

    /**
     * Verifies that this CRL was signed using the
     * private key that corresponds to the given public key,
     * and that the signature verification was computed by
     * the given provider.
     *
     * @param key the PublicKey used to carry out the verification.
     * @param sigProvider the name of the signature provider.
     *
     * @exception NoSuchAlgorithmException on unsupported signature
     * algorithms.
     * @exception InvalidKeyException on incorrect key.
     * @exception NoSuchProviderException on incorrect provider.
     * @exception SignatureException on signature errors.
     * @exception CRLException on encoding errors.
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    public synchronized void verify(PublicKey key, String sigProvider)
            throws CRLException, NoSuchAlgorithmException, InvalidKeyException,
            NoSuchProviderException, SignatureException {

        if (sigProvider == null) {
            sigProvider = "";
        }
        if ((verifiedPublicKey != null) && verifiedPublicKey.equals(key)) {
            // this CRL has already been successfully verified using
            // this public key. Make sure providers match, too.
            if (sigProvider.equals(verifiedProvider)) {
                return;
            }
        }
        if (signedCRL == null) {
            throw new CRLException("Uninitialized CRL");
        }
        Signature   sigVerf;
        if (sigProvider.isEmpty()) {
            sigVerf = Signature.getInstance(sigAlgId.getName());
        } else {
            sigVerf = Signature.getInstance(sigAlgId.getName(), sigProvider);
        }
        sigVerf.initVerify(key);

        if (tbsCertList == null) {
            throw new CRLException("Uninitialized CRL");
        }

        sigVerf.update(tbsCertList, 0, tbsCertList.length);

        if (!sigVerf.verify(signature)) {
            throw new SignatureException("Signature does not match.");
        }
        verifiedPublicKey = key;
        verifiedProvider = sigProvider;
    }

    /**
     * Encodes an X.509 CRL, and signs it using the given key.
     *
     * @param key the private key used for signing.
     * @param algorithm the name of the signature algorithm used.
     *
     * @exception NoSuchAlgorithmException on unsupported signature
     * algorithms.
     * @exception InvalidKeyException on incorrect key.
     * @exception NoSuchProviderException on incorrect provider.
     * @exception SignatureException on signature errors.
     * @exception CRLException if any mandatory data was omitted.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public void sign(PrivateKey key, String algorithm)
    throws CRLException, NoSuchAlgorithmException, InvalidKeyException,
        NoSuchProviderException, SignatureException {
        sign(key, algorithm, null);
    }

    /**
     * Encodes an X.509 CRL, and signs it using the given key.
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
     * @exception CRLException if any mandatory data was omitted.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public void sign(PrivateKey key, String algorithm, String provider)
    throws CRLException, NoSuchAlgorithmException, InvalidKeyException,
        NoSuchProviderException, SignatureException {
        try {
            if (readOnly)
                throw new CRLException("cannot over-write existing CRL");
            Signature sigEngine;
            if ((provider == null) || (provider.isEmpty()))
                sigEngine = Signature.getInstance(algorithm);
            else
                sigEngine = Signature.getInstance(algorithm, provider);

            sigEngine.initSign(key);

                                // in case the name is reset
            sigAlgId = AlgorithmId.get(sigEngine.getAlgorithm());
            infoSigAlgId = sigAlgId;

            DerOutputStream out = new DerOutputStream();
            DerOutputStream tmp = new DerOutputStream();

            // encode crl info
            encodeInfo(tmp);

            // encode algorithm identifier
            sigAlgId.encode(tmp);

            // Create and encode the signature itself.
            sigEngine.update(tbsCertList, 0, tbsCertList.length);
            signature = sigEngine.sign();
            tmp.putBitString(signature);

            // Wrap the signed data in a SEQUENCE { data, algorithm, sig }
            out.write(DerValue.tag_Sequence, tmp);
            signedCRL = out.toByteArray();
            readOnly = true;

        } catch (IOException e) {
            throw new CRLException("Error while encoding data: " +
                                   e.getMessage());
        }
    }

    /**
     * Returns a printable string of this CRL.
     *
     * @return value of this CRL in a printable form.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    @NonNull
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("X.509 CRL v").append(version + 1).append("\n");
        if (sigAlgId != null)
            sb.append("Signature Algorithm: ").append(sigAlgId.toString()).append(", OID=").append((sigAlgId.getOID()).toString()).append("\n");
        if (issuer != null)
            sb.append("Issuer: ").append(issuer.toString()).append("\n");
        if (thisUpdate != null)
            sb.append("\nThis Update: ").append(thisUpdate.toString()).append("\n");
        if (nextUpdate != null)
            sb.append("Next Update: ").append(nextUpdate.toString()).append("\n");
        if (revokedCerts.isEmpty())
            sb.append("\nNO certificates have been revoked\n");
        else {
            sb.append("\nRevoked Certificates: ").append(revokedCerts.size());
            int i = 1;
            for (Iterator<X509CRLEntry> iter = revokedCerts.values().iterator();
                                             iter.hasNext(); i++)
                sb.append("\n[").append(i).append("] ").append(iter.next().toString());
        }
        if (extensions != null) {
            Collection<Extension> allExts = extensions.getAllExtensions();
            Object[] objs = allExts.toArray();
            sb.append("\nCRL Extensions: ").append(objs.length);
            for (int i = 0; i < objs.length; i++) {
                sb.append("\n[").append(i + 1).append("]: ");
                Extension ext = (Extension)objs[i];
                try {
                   if (OIDMap.getClass(ext.getExtensionId()) == null) {
                       sb.append(ext);
                       byte[] extValue = ext.getExtensionValue();
                       if (extValue != null) {
                           DerOutputStream out = new DerOutputStream();
                           out.putOctetString(extValue);
                           extValue = out.toByteArray();
                           HexDumpEncoder enc = new HexDumpEncoder();
                           sb.append("Extension unknown: " + "DER encoded OCTET string =\n").append(enc.encodeBuffer(extValue)).append("\n");
                      }
                   } else
                       sb.append(ext); // sub-class exists
                } catch (Exception e) {
                    sb.append(", Error parsing this extension");
                }
            }
        }
        if (signature != null) {
            HexDumpEncoder encoder = new HexDumpEncoder();
            sb.append("\nSignature:\n").append(encoder.encodeBuffer(signature)).append("\n");
        } else
            sb.append("NOT signed yet\n");
        return sb.toString();
    }

    /**
     * Checks whether the given certificate is on this CRL.
     *
     * @param cert the certificate to check for.
     * @return true if the given certificate is on this CRL,
     * false otherwise.
     */
    public boolean isRevoked(Certificate cert) {
        if (revokedCerts.isEmpty() || (!(cert instanceof X509Certificate))) {
            return false;
        }
        X509Certificate xcert = (X509Certificate) cert;
        X509IssuerSerial issuerSerial = new X509IssuerSerial(xcert);
        return revokedCerts.containsKey(issuerSerial);
    }

    /**
     * Gets the version number from this CRL.
     * The ASN.1 definition for this is:
     * <pre>
     * Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     *             -- v3 does not apply to CRLs but appears for consistency
     *             -- with definition of Version for certs
     * </pre>
     * @return the version number, i.e. 1 or 2.
     */
    public int getVersion() {
        return version+1;
    }

    /**
     * Gets the issuer distinguished name from this CRL.
     * The issuer name identifies the entity who has signed (and
     * issued the CRL). The issuer name field contains an
     * X.500 distinguished name (DN).
     * The ASN.1 definition for this is:
     * <pre>
     * issuer    Name
     *
     * Name ::= CHOICE { RDNSequence }
     * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
     * RelativeDistinguishedName ::=
     *     SET OF AttributeValueAssertion
     *
     * AttributeValueAssertion ::= SEQUENCE {
     *                               AttributeType,
     *                               AttributeValue }
     * AttributeType ::= OBJECT IDENTIFIER
     * AttributeValue ::= ANY
     * </pre>
     * The Name describes a hierarchical name composed of attributes,
     * such as country name, and corresponding values, such as US.
     * The type of the component AttributeValue is determined by the
     * AttributeType; in general it will be a directoryString.
     * A directoryString is usually one of PrintableString,
     * TeletexString or UniversalString.
     * @return the issuer name.
     */
    public Principal getIssuerDN() {
        return (Principal)issuer;
    }

    /**
     * Return the issuer as X500Principal. Overrides method in X509CRL
     * to provide a slightly more efficient version.
     */
    public X500Principal getIssuerX500Principal() {
        if (issuerPrincipal == null) {
            issuerPrincipal = issuer.asX500Principal();
        }
        return issuerPrincipal;
    }

    /**
     * Gets the thisUpdate date from the CRL.
     * The ASN.1 definition for this is:
     *
     * @return the thisUpdate date from the CRL.
     */
    public Date getThisUpdate() {
        return (new Date(thisUpdate.getTime()));
    }

    /**
     * Gets the nextUpdate date from the CRL.
     *
     * @return the nextUpdate date from the CRL, or null if
     * not present.
     */
    public Date getNextUpdate() {
        if (nextUpdate == null)
            return null;
        return (new Date(nextUpdate.getTime()));
    }

    /**
     * Gets the CRL entry with the given serial number from this CRL.
     *
     * @return the entry with the given serial number, or <code>null</code> if
     * no such entry exists in the CRL.
     * @see X509CRLEntry
     */
    public X509CRLEntry getRevokedCertificate(BigInteger serialNumber) {
        if (revokedCerts.isEmpty()) {
            return null;
        }
        // assume this is a direct CRL entry (cert and CRL issuer are the same)
        X509IssuerSerial issuerSerial = new X509IssuerSerial
            (getIssuerX500Principal(), serialNumber);
        return revokedCerts.get(issuerSerial);
    }

    /**
     * Gets the CRL entry for the given certificate.
     */
    public X509CRLEntry getRevokedCertificate(X509Certificate cert) {
        if (revokedCerts.isEmpty()) {
            return null;
        }
        X509IssuerSerial issuerSerial = new X509IssuerSerial(cert);
        return revokedCerts.get(issuerSerial);
    }

    /**
     * Gets all the revoked certificates from the CRL.
     * A Set of X509CRLEntry.
     *
     * @return all the revoked certificates or <code>null</code> if there are
     * none.
     * @see X509CRLEntry
     */
    public Set<X509CRLEntry> getRevokedCertificates() {
        if (revokedCerts.isEmpty()) {
            return null;
        } else {
            return new HashSet<>(revokedCerts.values());
        }
    }

    /**
     * Gets the DER encoded CRL information, the
     * <code>tbsCertList</code> from this CRL.
     * This can be used to verify the signature independently.
     *
     * @return the DER encoded CRL information.
     * @exception CRLException on encoding errors.
     */
    public byte[] getTBSCertList() throws CRLException {
        if (tbsCertList == null)
            throw new CRLException("Uninitialized CRL");
        byte[] dup = new byte[tbsCertList.length];
        System.arraycopy(tbsCertList, 0, dup, 0, dup.length);
        return dup;
    }

    /**
     * Gets the raw Signature bits from the CRL.
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
     * Gets the signature algorithm name for the CRL
     * signature algorithm. For example, the string "SHA1withDSA".
     * The ASN.1 definition for this is:
     * <pre>
     * AlgorithmIdentifier  ::=  SEQUENCE  {
     *     algorithm               OBJECT IDENTIFIER,
     *     parameters              ANY DEFINED BY algorithm OPTIONAL  }
     *                             -- contains a value of the type
     *                             -- registered for use with the
     *                             -- algorithm object identifier value
     * </pre>
     *
     * @return the signature algorithm name.
     */
    public String getSigAlgName() {
        if (sigAlgId == null)
            return null;
        return sigAlgId.getName();
    }

    /**
     * Gets the signature algorithm OID string from the CRL.
     * An OID is represented by a set of positive whole number separated
     * by ".", that means,<br>
     * &lt;positive whole number&gt;.&lt;positive whole number&gt;.&lt;...&gt;
     * For example, the string "1.2.840.10040.4.3" identifies the SHA-1
     * with DSA signature algorithm defined in
     * <a href="http://www.ietf.org/rfc/rfc3279.txt">RFC 3279: Algorithms and
     * Identifiers for the Internet X.509 Public Key Infrastructure Certificate
     * and CRL Profile</a>.
     *
     * @return the signature algorithm oid string.
     */
    public String getSigAlgOID() {
        if (sigAlgId == null)
            return null;
        ObjectIdentifier oid = sigAlgId.getOID();
        return oid.toString();
    }

    /**
     * Gets the DER encoded signature algorithm parameters from this
     * CRL's signature algorithm. In most cases, the signature
     * algorithm parameters are null, the parameters are usually
     * supplied with the Public Key.
     *
     * @return the DER encoded signature algorithm parameters, or
     *         null if no parameters are present.
     */
    public byte[] getSigAlgParams() {
        if (sigAlgId == null)
            return null;
        try {
            return sigAlgId.getEncodedParams();
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Return true if a critical extension is found that is
     * not supported, otherwise return false.
     */
    public boolean hasUnsupportedCriticalExtension() {
        if (extensions == null)
            return false;
        return extensions.hasUnsupportedCriticalExtension();
    }

    /**
     * Gets a Set of the extension(s) marked CRITICAL in the
     * CRL. In the returned set, each extension is represented by
     * its OID string.
     *
     * @return a set of the extension oid strings in the
     * CRL that are marked critical.
     */
    public Set<String> getCriticalExtensionOIDs() {
        if (extensions == null) {
            return null;
        }
        Set<String> extSet = new HashSet<>();
        for (Extension ex : extensions.getAllExtensions()) {
            if (ex.isCritical()) {
                extSet.add(ex.getExtensionId().toString());
            }
        }
        return extSet;
    }

    /**
     * Gets a Set of the extension(s) marked NON-CRITICAL in the
     * CRL. In the returned set, each extension is represented by
     * its OID string.
     *
     * @return a set of the extension oid strings in the
     * CRL that are NOT marked critical.
     */
    public Set<String> getNonCriticalExtensionOIDs() {
        if (extensions == null) {
            return null;
        }
        Set<String> extSet = new HashSet<>();
        for (Extension ex : extensions.getAllExtensions()) {
            if (!ex.isCritical()) {
                extSet.add(ex.getExtensionId().toString());
            }
        }
        return extSet;
    }

    /**
     * Gets the DER encoded OCTET string for the extension value
     * (<code>extnValue</code>) identified by the passed in oid String.
     * The <code>oid</code> string is
     * represented by a set of positive whole number separated
     * by ".", that means,<br>
     * &lt;positive whole number&gt;.&lt;positive whole number&gt;.&lt;...&gt;
     *
     * @param oid the Object Identifier value for the extension.
     * @return the der encoded octet string of the extension value.
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    public byte[] getExtensionValue(String oid) {
        if (extensions == null)
            return null;
        try {
            String extAlias = OIDMap.getName(new ObjectIdentifier(oid));
            Extension crlExt = null;

            if (extAlias == null) { // may be unknown
                ObjectIdentifier findOID = new ObjectIdentifier(oid);
                Extension ex;
                ObjectIdentifier inCertOID;
                for (Enumeration<Extension> e = extensions.getElements();
                     e.hasMoreElements();) {
                    ex = e.nextElement();
                    inCertOID = ex.getExtensionId();
                    if (inCertOID.equals(findOID)) {
                        crlExt = ex;
                        break;
                    }
                }
            } else
                crlExt = extensions.get(extAlias);
            if (crlExt == null)
                return null;
            byte[] extData = crlExt.getExtensionValue();
            if (extData == null)
                return null;
            DerOutputStream out = new DerOutputStream();
            out.putOctetString(extData);
            return out.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    /*
     * Parses an X.509 CRL, should be used only by constructors.
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    private void parse(DerValue val) throws CRLException, IOException {
        // check if can over write the certificate
        if (readOnly)
            throw new CRLException("cannot over-write existing CRL");

        if ( val.getData() == null || val.tag != DerValue.tag_Sequence)
            throw new CRLException("Invalid DER-encoded CRL data");

        signedCRL = val.toByteArray();
        DerValue[] seq = new DerValue[3];

        seq[0] = val.data.getDerValue();
        seq[1] = val.data.getDerValue();
        seq[2] = val.data.getDerValue();

        if (val.data.available() != 0)
            throw new CRLException("signed overrun, bytes = "
                                     + val.data.available());

        if (seq[0].tag != DerValue.tag_Sequence)
            throw new CRLException("signed CRL fields invalid");

        sigAlgId = AlgorithmId.parse(seq[1]);
        signature = seq[2].getBitString();

        if (seq[1].data.available() != 0)
            throw new CRLException("AlgorithmId field overrun");

        if (seq[2].data.available() != 0)
            throw new CRLException("Signature field overrun");

        // the tbsCertsList
        tbsCertList = seq[0].toByteArray();

        // parse the information
        DerInputStream derStrm = seq[0].data;
        DerValue tmp;
        byte           nextByte;

        // version (optional if v1)
        version = 0;   // by default, version = v1 == 0
        nextByte = (byte)derStrm.peekByte();
        if (nextByte == DerValue.tag_Integer) {
            version = derStrm.getInteger();
            if (version != 1)  // i.e. v2
                throw new CRLException("Invalid version");
        }
        tmp = derStrm.getDerValue();

        // signature
        AlgorithmId tmpId = AlgorithmId.parse(tmp);

        // the "inner" and "outer" signature algorithms must match
        if (! tmpId.equals(sigAlgId))
            throw new CRLException("Signature algorithm mismatch");
        infoSigAlgId = tmpId;

        // issuer
        issuer = new X500Name(derStrm);
        if (issuer.isEmpty()) {
            throw new CRLException("Empty issuer DN not allowed in X509CRLs");
        }

        // thisUpdate
        // check if UTCTime encoded or GeneralizedTime

        nextByte = (byte)derStrm.peekByte();
        if (nextByte == DerValue.tag_UtcTime) {
            thisUpdate = derStrm.getUTCTime();
        } else if (nextByte == DerValue.tag_GeneralizedTime) {
            thisUpdate = derStrm.getGeneralizedTime();
        } else {
            throw new CRLException("Invalid encoding for thisUpdate"
                                   + " (tag=" + nextByte + ")");
        }

        if (derStrm.available() == 0)
           return;     // done parsing no more optional fields present

        // nextUpdate (optional)
        nextByte = (byte)derStrm.peekByte();
        if (nextByte == DerValue.tag_UtcTime) {
            nextUpdate = derStrm.getUTCTime();
        } else if (nextByte == DerValue.tag_GeneralizedTime) {
            nextUpdate = derStrm.getGeneralizedTime();
        } // else it is not present

        if (derStrm.available() == 0)
            return;     // done parsing no more optional fields present

        // revokedCertificates (optional)
        nextByte = (byte)derStrm.peekByte();
        if ((nextByte == DerValue.tag_SequenceOf)) {
            DerValue[] badCerts = derStrm.getSequence(4);

            X500Principal crlIssuer = getIssuerX500Principal();
            X500Principal badCertIssuer = crlIssuer;
            for (DerValue badCert : badCerts) {
                X509CRLEntryImpl entry = new X509CRLEntryImpl(badCert);
                badCertIssuer = getCertIssuer(entry, badCertIssuer);
                entry.setCertificateIssuer(crlIssuer, badCertIssuer);
                X509IssuerSerial issuerSerial = new X509IssuerSerial
                        (badCertIssuer, entry.getSerialNumber());
                revokedCerts.put(issuerSerial, entry);
            }
        }

        if (derStrm.available() == 0)
            return;     // done parsing no extensions

        // crlExtensions (optional)
        tmp = derStrm.getDerValue();
        if (tmp.isConstructed() && tmp.isContextSpecific((byte)0)) {
            extensions = new CRLExtensions(tmp.data);
        }
        readOnly = true;
    }

    /**
     * Returns the X500 certificate issuer DN of a CRL entry.
     *
     * @param entry the entry to check
     * @param prevCertIssuer the previous entry's certificate issuer
     * @return the X500Principal in a CertificateIssuerExtension, or
     *   prevCertIssuer if it does not exist
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    private X500Principal getCertIssuer(X509CRLEntryImpl entry,
                                        X500Principal prevCertIssuer) throws IOException {

        CertificateIssuerExtension ciExt =
            entry.getCertificateIssuerExtension();
        if (ciExt != null) {
            GeneralNames names = (GeneralNames)
                ciExt.get(CertificateIssuerExtension.ISSUER);
            X500Name issuerDN = (X500Name) names.get(0).getName();
            return issuerDN.asX500Principal();
        } else {
            return prevCertIssuer;
        }
    }

    @Override
    public void derEncode(OutputStream out) throws IOException {
        if (signedCRL == null)
            throw new IOException("Null CRL to encode");
        out.write(signedCRL.clone());
    }

    /**
     * Immutable X.509 Certificate Issuer DN and serial number pair
     */
    private final static class X509IssuerSerial {
        final X500Principal issuer;
        final BigInteger serial;
        volatile int hashcode = 0;

        /**
         * Create an X509IssuerSerial.
         *
         * @param issuer the issuer DN
         * @param serial the serial number
         */
        X509IssuerSerial(X500Principal issuer, BigInteger serial) {
            this.issuer = issuer;
            this.serial = serial;
        }

        /**
         * Construct an X509IssuerSerial from an X509Certificate.
         */
        X509IssuerSerial(X509Certificate cert) {
            this(cert.getIssuerX500Principal(), cert.getSerialNumber());
        }

        /**
         * Returns the issuer.
         *
         * @return the issuer
         */
        X500Principal getIssuer() {
            return issuer;
        }

        /**
         * Returns the serial number.
         *
         * @return the serial number
         */
        BigInteger getSerial() {
            return serial;
        }

        /**
         * Compares this X509Serial with another and returns true if they
         * are equivalent.
         *
         * @param o the other object to compare with
         * @return true if equal, false otherwise
         */
        public boolean equals(Object o) {
            if (o == this) {
                return true;
            }

            if (!(o instanceof X509IssuerSerial)) {
                return false;
            }

            X509IssuerSerial other = (X509IssuerSerial) o;
            return serial.equals(other.getSerial()) &&
                    issuer.equals(other.getIssuer());
        }

        /**
         * Returns a hash code value for this X509IssuerSerial.
         *
         * @return the hash code value
         */
        public int hashCode() {
            if (hashcode == 0) {
                int result = 17;
                result = 37*result + issuer.hashCode();
                result = 37*result + serial.hashCode();
                hashcode = result;
            }
            return hashcode;
        }
    }
}