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

package com.apk.jks.pkcs;

import com.apk.jks.utils.HexDumpEncoder;
import com.apk.jks.utils.Debug;
import com.apk.jks.utils.DerEncoder;
import com.apk.jks.utils.DerInputStream;
import com.apk.jks.utils.DerOutputStream;
import com.apk.jks.utils.DerValue;
import com.apk.jks.utils.ObjectIdentifier;
import com.apk.jks.x509.AlgorithmId;
import com.apk.jks.x509.KeyUsageExtension;
import com.apk.jks.x509.X500Name;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;

public class SignerInfo implements DerEncoder {

    BigInteger version;
    X500Name issuerName;
    BigInteger certificateSerialNumber;
    AlgorithmId digestAlgorithmId;
    AlgorithmId digestEncryptionAlgorithmId;
    byte[] encryptedDigest;

    PKCS9Attributes authenticatedAttributes;
    PKCS9Attributes unauthenticatedAttributes;

    /**
     * Parses a PKCS#7 signer info.
     */
    public SignerInfo(DerInputStream derin)
        throws IOException {
        this(derin, false);
    }

    /**
     * Parses a PKCS#7 signer info.
     *
     * <p>This constructor is used only for backwards compatibility with
     * PKCS#7 blocks that were generated using JDK1.1.x.
     *
     * @param derin the ASN.1 encoding of the signer info.
     * @param oldStyle flag indicating whether or not the given signer info
     * is encoded according to JDK1.1.x.
     */
    public SignerInfo(DerInputStream derin, boolean oldStyle)
        throws IOException {
        // version
        version = derin.getBigInteger();

        // issuerAndSerialNumber
        DerValue[] issuerAndSerialNumber = derin.getSequence(2);
        byte[] issuerBytes = issuerAndSerialNumber[0].toByteArray();
        issuerName = new X500Name(new DerValue(DerValue.tag_Sequence,
                                               issuerBytes));
        certificateSerialNumber = issuerAndSerialNumber[1].getBigInteger();

        // digestAlgorithmId
        DerValue tmp = derin.getDerValue();

        digestAlgorithmId = AlgorithmId.parse(tmp);

        // authenticatedAttributes
        if (oldStyle) {
            // In JDK1.1.x, the authenticatedAttributes are always present,
            // encoded as an empty Set (Set of length zero)
            derin.getSet(0);
        } else {
            // check if set of auth attributes (implicit tag) is provided
            // (auth attributes are OPTIONAL)
            if ((byte)(derin.peekByte()) == (byte)0xA0) {
                authenticatedAttributes = new PKCS9Attributes(derin);
            }
        }

        // digestEncryptionAlgorithmId - little RSA naming scheme -
        // signature == encryption...
        tmp = derin.getDerValue();

        digestEncryptionAlgorithmId = AlgorithmId.parse(tmp);

        // encryptedDigest
        encryptedDigest = derin.getOctetString();

        // unauthenticatedAttributes
        if (oldStyle) {
            // In JDK1.1.x, the unauthenticatedAttributes are always present,
            // encoded as an empty Set (Set of length zero)
            derin.getSet(0);
        } else {
            // check if set of unauth attributes (implicit tag) is provided
            // (unauth attributes are OPTIONAL)
            if (derin.available() != 0
                && (byte)(derin.peekByte()) == (byte)0xA1) {
                unauthenticatedAttributes =
                    new PKCS9Attributes(derin, true);// ignore unsupported attrs
            }
        }

        // all done
        if (derin.available() != 0) {
            throw new ParsingException("extra data at the end");
        }
    }

    public void encode(DerOutputStream out) throws IOException {

        derEncode(out);
    }

    /**
     * DER encode this object onto an output stream.
     * Implements the <code>DerEncoder</code> interface.
     *
     * @param out
     * the output stream on which to write the DER encoding.
     *
     * @exception IOException on encoding error.
     */
    public void derEncode(OutputStream out) throws IOException {
        DerOutputStream seq = new DerOutputStream();
        seq.putInteger(version);
        DerOutputStream issuerAndSerialNumber = new DerOutputStream();
        issuerName.encode(issuerAndSerialNumber);
        issuerAndSerialNumber.putInteger(certificateSerialNumber);
        seq.write(DerValue.tag_Sequence, issuerAndSerialNumber);

        digestAlgorithmId.encode(seq);

        // encode authenticated attributes if there are any
        if (authenticatedAttributes != null)
            authenticatedAttributes.encode((byte)0xA0, seq);

        digestEncryptionAlgorithmId.encode(seq);

        seq.putOctetString(encryptedDigest);

        // encode unauthenticated attributes if there are any
        if (unauthenticatedAttributes != null)
            unauthenticatedAttributes.encode((byte)0xA1, seq);

        DerOutputStream tmp = new DerOutputStream();
        tmp.write(DerValue.tag_Sequence, seq);

        out.write(tmp.toByteArray());
    }

    /*
     * Returns the (user) certificate pertaining to this SignerInfo.
     */
    public X509Certificate getCertificate(PKCS7 block)
        throws IOException
    {
        return block.getCertificate(certificateSerialNumber, issuerName);
    }

    /* Returns null if verify fails, this signerInfo if
       verify succeeds. */
    SignerInfo verify(PKCS7 block, byte[] data)
    throws NoSuchAlgorithmException, SignatureException {

        try {

            ContentInfo content = block.getContentInfo();
            if (data == null) {
                data = content.getContentBytes();
            }

            String digestAlgname = getDigestAlgorithmId().getName();

            byte[] dataSigned;

            // if there are authenticate attributes, get the message
            // digest and compare it with the digest of data
            if (authenticatedAttributes == null) {
                dataSigned = data;
            } else {

                // first, check content type
                ObjectIdentifier contentType = (ObjectIdentifier)
                       authenticatedAttributes.getAttributeValue(
                         PKCS9Attribute.CONTENT_TYPE_OID);
                if (contentType == null ||
                    !contentType.equals(content.contentType))
                    return null;  // contentType does not match, bad SignerInfo

                // now, check message digest
                byte[] messageDigest = (byte[])
                    authenticatedAttributes.getAttributeValue(
                         PKCS9Attribute.MESSAGE_DIGEST_OID);

                if (messageDigest == null) // fail if there is no message digest
                    return null;

                MessageDigest md = MessageDigest.getInstance(digestAlgname);
                byte[] computedMessageDigest = md.digest(data);

                if (messageDigest.length != computedMessageDigest.length)
                    return null;
                for (int i = 0; i < messageDigest.length; i++) {
                    if (messageDigest[i] != computedMessageDigest[i])
                        return null;
                }

                // message digest attribute matched
                // digest of original data

                // the data actually signed is the DER encoding of
                // the authenticated attributes (tagged with
                // the "SET OF" tag, not 0xA0).
                dataSigned = authenticatedAttributes.getDerEncoding();
            }

            // put together digest algorithm and encryption algorithm
            // to form signing algorithm
            String encryptionAlgname =
                getDigestEncryptionAlgorithmId().getName();

            // Workaround: sometimes the encryptionAlgname is actually
            // a signature name
            String tmp = AlgorithmId.getEncAlgFromSigAlg(encryptionAlgname);
            if (tmp != null) encryptionAlgname = tmp;
            String algname = AlgorithmId.makeSigAlg(
                    digestAlgname, encryptionAlgname);

            Signature sig = Signature.getInstance(algname);
            X509Certificate cert = getCertificate(block);

            if (cert == null) {
                return null;
            }
            if (cert.hasUnsupportedCriticalExtension()) {
                throw new SignatureException("Certificate has unsupported "
                                             + "critical extension(s)");
            }

            // Make sure that if the usage of the key in the certificate is
            // restricted, it can be used for digital signatures.
            // XXX We may want to check for additional extensions in the
            // future.
            boolean[] keyUsageBits = cert.getKeyUsage();
            if (keyUsageBits != null) {
                KeyUsageExtension keyUsage = getKeyUsageExtension(keyUsageBits);

                boolean digSigAllowed = (Boolean) keyUsage.get(
                        KeyUsageExtension.DIGITAL_SIGNATURE);

                boolean nonRepuAllowed = (Boolean) keyUsage.get(
                        KeyUsageExtension.NON_REPUDIATION);

                if (!digSigAllowed && !nonRepuAllowed) {
                    throw new SignatureException("Key usage restricted: "
                                                 + "cannot be used for "
                                                 + "digital signatures");
                }
            }

            PublicKey key = cert.getPublicKey();
            sig.initVerify(key);

            sig.update(dataSigned);

            if (sig.verify(encryptedDigest)) {
                return this;
            }

        } catch (IOException e) {
            throw new SignatureException("IO error verifying signature:\n" +
                                         e.getMessage());

        } catch (InvalidKeyException e) {
            throw new SignatureException("InvalidKey: " + e.getMessage());

        }
        return null;
    }

    @NonNull
    private static KeyUsageExtension getKeyUsageExtension(boolean[] keyUsageBits) throws SignatureException {
        KeyUsageExtension keyUsage;
        try {
            // We don't care whether or not this extension was marked
            // critical in the certificate.
            // We're interested only in its value (i.e., the bits set)
            // and treat the extension as critical.
            keyUsage = new KeyUsageExtension(keyUsageBits);
        } catch (IOException ioe) {
            throw new SignatureException("Failed to parse keyUsage "
                                         + "extension");
        }
        return keyUsage;
    }


    public BigInteger getVersion() {
            return version;
    }

    public AlgorithmId getDigestAlgorithmId() {
        return digestAlgorithmId;
    }

    public AlgorithmId getDigestEncryptionAlgorithmId() {
        return digestEncryptionAlgorithmId;
    }

    @NonNull
    public String toString() {
        HexDumpEncoder hexDump = new HexDumpEncoder();

        String out = "";

        out += "Signer Info for (issuer): " + issuerName + "\n";
        out += "\tversion: " + Debug.toHexString(version) + "\n";
        out += "\tcertificateSerialNumber: " +
               Debug.toHexString(certificateSerialNumber) + "\n";
        out += "\tdigestAlgorithmId: " + digestAlgorithmId + "\n";
        if (authenticatedAttributes != null) {
            out += "\tauthenticatedAttributes: " + authenticatedAttributes +
                   "\n";
        }
        out += "\tdigestEncryptionAlgorithmId: " + digestEncryptionAlgorithmId +
            "\n";

        out += "\tencryptedDigest: " + "\n" +
            hexDump.encodeBuffer(encryptedDigest) + "\n";
        if (unauthenticatedAttributes != null) {
            out += "\tunauthenticatedAttributes: " +
                   unauthenticatedAttributes + "\n";
        }
        return out;
    }

}