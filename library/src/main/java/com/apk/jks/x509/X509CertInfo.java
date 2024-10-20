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

import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import com.apk.jks.utils.HexDumpEncoder;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import com.apk.jks.utils.DerInputStream;
import com.apk.jks.utils.DerOutputStream;

public class X509CertInfo implements CertAttrSet<String> {

    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info";
    // Certificate attribute names
    public static final String NAME = "info";
    public static final String VERSION = CertificateVersion.NAME;
    public static final String SERIAL_NUMBER = CertificateSerialNumber.NAME;
    public static final String ALGORITHM_ID = CertificateAlgorithmId.NAME;
    public static final String ISSUER = CertificateIssuerName.NAME;
    public static final String VALIDITY = CertificateValidity.NAME;
    public static final String SUBJECT = CertificateSubjectName.NAME;
    public static final String KEY = CertificateX509Key.NAME;
    public static final String ISSUER_ID = CertificateIssuerUniqueIdentity.NAME;
    public static final String SUBJECT_ID = CertificateSubjectUniqueIdentity.NAME;
    public static final String EXTENSIONS = CertificateExtensions.NAME;

    // X509.v1 data
    protected CertificateVersion version = new CertificateVersion();
    protected CertificateSerialNumber serialNum = null;
    protected CertificateAlgorithmId algId = null;
    protected CertificateIssuerName issuer = null;
    protected CertificateValidity interval = null;
    protected CertificateSubjectName subject = null;
    protected CertificateX509Key pubKey = null;

    // X509.v2 & v3 extensions
    protected CertificateIssuerUniqueIdentity   issuerUniqueId = null;
    protected CertificateSubjectUniqueIdentity  subjectUniqueId = null;

    // X509.v3 extensions
    protected CertificateExtensions extensions = null;

    // Attribute numbers for internal manipulation
    private static final int ATTR_VERSION = 1;
    private static final int ATTR_SERIAL = 2;
    private static final int ATTR_ALGORITHM = 3;
    private static final int ATTR_ISSUER = 4;
    private static final int ATTR_VALIDITY = 5;
    private static final int ATTR_SUBJECT = 6;
    private static final int ATTR_KEY = 7;
    private static final int ATTR_ISSUER_ID = 8;
    private static final int ATTR_SUBJECT_ID = 9;
    private static final int ATTR_EXTENSIONS = 10;

    // DER encoded CertificateInfo data
    private byte[]      rawCertInfo = null;

    // The certificate attribute name to integer mapping stored here
    private static final Map<String,Integer> map = new HashMap<>();
    static {
        map.put(VERSION, ATTR_VERSION);
        map.put(SERIAL_NUMBER, ATTR_SERIAL);
        map.put(ALGORITHM_ID, ATTR_ALGORITHM);
        map.put(ISSUER, ATTR_ISSUER);
        map.put(VALIDITY, ATTR_VALIDITY);
        map.put(SUBJECT, ATTR_SUBJECT);
        map.put(KEY, ATTR_KEY);
        map.put(ISSUER_ID, ATTR_ISSUER_ID);
        map.put(SUBJECT_ID, ATTR_SUBJECT_ID);
        map.put(EXTENSIONS, ATTR_EXTENSIONS);
    }

    /*
     * Unmarshals a certificate from its encoded form, parsing the
     * encoded bytes.  This form of constructor is used by agents which
     * need to examine and use certificate contents.  That is, this is
     * one of the more commonly used constructors.  Note that the buffer
     * must include only a certificate, and no "garbage" may be left at
     * the end.  If you need to ignore data at the end of a certificate,
     * use another constructor.
     *
     * @param cert the encoded bytes, with no trailing data.
     * @exception CertificateParsingException on parsing errors.
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    public X509CertInfo(byte[] cert) throws CertificateParsingException {
        try {
            DerValue in = new DerValue(cert);

            parse(in);
        } catch (IOException e) {
            throw new CertificateParsingException(e.toString(), e);
        }
    }

    /**
     * Unmarshal a certificate from its encoded form, parsing a DER value.
     * This form of constructor is used by agents which need to examine
     * and use certificate contents.
     *
     * @param derVal the der value containing the encoded cert.
     * @exception CertificateParsingException on parsing errors.
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    public X509CertInfo(DerValue derVal) throws CertificateParsingException {
        try {
            parse(derVal);
        } catch (IOException e) {
            throw new CertificateParsingException(e.toString(), e);
        }
    }

    /**
     * Appends the certificate to an output stream.
     *
     * @param out an output stream to which the certificate is appended.
     * @exception CertificateException on encoding errors.
     * @exception IOException on other errors.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public void encode(OutputStream out)
    throws CertificateException, IOException {
        if (rawCertInfo == null) {
            DerOutputStream tmp = new DerOutputStream();
            emit(tmp);
            rawCertInfo = tmp.toByteArray();
        }
        out.write(rawCertInfo.clone());
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getElements() {
        AttributeNameEnumeration elements = new AttributeNameEnumeration();
        elements.addElement(VERSION);
        elements.addElement(SERIAL_NUMBER);
        elements.addElement(ALGORITHM_ID);
        elements.addElement(ISSUER);
        elements.addElement(VALIDITY);
        elements.addElement(SUBJECT);
        elements.addElement(KEY);
        elements.addElement(ISSUER_ID);
        elements.addElement(SUBJECT_ID);
        elements.addElement(EXTENSIONS);

        return elements.elements();
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return(NAME);
    }

    /*
     * Returns the encoded certificate info.
     *
     * @exception CertificateEncodingException on encoding information errors.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public byte[] getEncodedInfo() throws CertificateEncodingException {
        try {
            if (rawCertInfo == null) {
                DerOutputStream tmp = new DerOutputStream();
                emit(tmp);
                rawCertInfo = tmp.toByteArray();
            }
            return rawCertInfo.clone();
        } catch (IOException | CertificateException e) {
            throw new CertificateEncodingException(e.toString());
        }
    }

    /**
     * Compares two X509CertInfo objects.  This is false if the
     * certificates are not both X.509 certs, otherwise it
     * compares them as binary data.
     *
     * @param other the object being compared with this one
     * @return true iff the certificates are equivalent
     */
    public boolean equals(Object other) {
        if (other instanceof X509CertInfo) {
            return equals((X509CertInfo) other);
        } else {
            return false;
        }
    }

    /**
     * Compares two certificates, returning false if any data
     * differs between the two.
     *
     * @param other the object being compared with this one
     * @return true iff the certificates are equivalent
     */
    public boolean equals(X509CertInfo other) {
        if (this == other) {
            return(true);
        } else if (rawCertInfo == null || other.rawCertInfo == null) {
            return(false);
        } else if (rawCertInfo.length != other.rawCertInfo.length) {
            return(false);
        }
        for (int i = 0; i < rawCertInfo.length; i++) {
            if (rawCertInfo[i] != other.rawCertInfo[i]) {
                return(false);
            }
        }
        return(true);
    }

    /**
     * Calculates a hash code value for the object.  Objects
     * which are equal will also have the same hashcode.
     */
    public int hashCode() {
        int     retval = 0;

        for (int i = 1; i < rawCertInfo.length; i++) {
            retval += rawCertInfo[i] * i;
        }
        return(retval);
    }

    /**
     * Returns a printable representation of the certificate.
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    @NonNull
    public String toString() {

        if (subject == null || pubKey == null || interval == null
            || issuer == null || algId == null || serialNum == null) {
                throw new NullPointerException("X.509 cert is incomplete");
        }
        StringBuilder sb = new StringBuilder();

        sb.append("[\n");
        sb.append("  ").append(version.toString()).append("\n");
        sb.append("  Subject: ").append(subject.toString()).append("\n");
        sb.append("  Signature Algorithm: ").append(algId.toString()).append("\n");
        sb.append("  Key:  ").append(pubKey.toString()).append("\n");
        sb.append("  ").append(interval.toString()).append("\n");
        sb.append("  Issuer: ").append(issuer.toString()).append("\n");
        sb.append("  ").append(serialNum.toString()).append("\n");

        // optional v2, v3 extras
        if (issuerUniqueId != null) {
            sb.append("  Issuer Id:\n").append(issuerUniqueId.toString()).append("\n");
        }
        if (subjectUniqueId != null) {
            sb.append("  Subject Id:\n").append(subjectUniqueId.toString()).append("\n");
        }
        if (extensions != null) {
            Collection<Extension> allExts = extensions.getAllExtensions();
            Object[] objs = allExts.toArray();
            sb.append("\nCertificate Extensions: ").append(objs.length);
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
                        sb.append(ext); //sub-class exists
                } catch (Exception e) {
                    sb.append(", Error parsing this extension");
                }
            }
            Map<String, Extension> invalid = extensions.getUnparseableExtensions();
            if (!invalid.isEmpty()) {
                sb.append("\nUnparseable certificate extensions: ").append(invalid.size());
                int i = 1;
                for (Extension ext : invalid.values()) {
                    sb.append("\n[").append(i++).append("]: ");
                    sb.append(ext);
                }
            }
        }
        sb.append("\n]");
        return sb.toString();
    }

    /*
     * Set the certificate attribute.
     *
     * @params name the name of the Certificate attribute.
     * @params val the value of the Certificate attribute.
     * @exception CertificateException on invalid attributes.
     * @exception IOException on other errors.
     */
    public void set(String name, Object val)
    throws CertificateException, IOException {
        X509AttributeName attrName = new X509AttributeName(name);

        int attr = attributeMap(attrName.getPrefix());
        if (attr == 0) {
            throw new CertificateException("Attribute name not recognized: "
                                           + name);
        }
        // set rawCertInfo to null, so that we are forced to re-encode
        rawCertInfo = null;
        String suffix = attrName.getSuffix();

        switch (attr) {
        case ATTR_VERSION:
            if (suffix == null) {
                setVersion(val);
            } else {
                version.set(suffix, val);
            }
            break;

        case ATTR_SERIAL:
            if (suffix == null) {
                setSerialNumber(val);
            } else {
                serialNum.set(suffix, val);
            }
            break;

        case ATTR_ALGORITHM:
            if (suffix == null) {
                setAlgorithmId(val);
            } else {
                algId.set(suffix, val);
            }
            break;

        case ATTR_ISSUER:
            if (suffix == null) {
                setIssuer(val);
            } else {
                issuer.set(suffix, val);
            }
            break;

        case ATTR_VALIDITY:
            if (suffix == null) {
                setValidity(val);
            } else {
                interval.set(suffix, val);
            }
            break;

        case ATTR_SUBJECT:
            if (suffix == null) {
                setSubject(val);
            } else {
                subject.set(suffix, val);
            }
            break;

        case ATTR_KEY:
            if (suffix == null) {
                setKey(val);
            } else {
                pubKey.set(suffix, val);
            }
            break;

        case ATTR_ISSUER_ID:
            if (suffix == null) {
                setIssuerUniqueId(val);
            } else {
                issuerUniqueId.set(suffix, val);
            }
            break;

        case ATTR_SUBJECT_ID:
            if (suffix == null) {
                setSubjectUniqueId(val);
            } else {
                subjectUniqueId.set(suffix, val);
            }
            break;

        case ATTR_EXTENSIONS:
            if (suffix == null) {
                setExtensions(val);
            } else {
                if (extensions == null)
                    extensions = new CertificateExtensions();
                extensions.set(suffix, val);
            }
            break;
        }
    }

    /*
     * Delete the certificate attribute.
     *
     * @params name the name of the Certificate attribute.
     * @exception CertificateException on invalid attributes.
     * @exception IOException on other errors.
     */
    public void delete(String name)
    throws CertificateException, IOException {
        X509AttributeName attrName = new X509AttributeName(name);

        int attr = attributeMap(attrName.getPrefix());
        if (attr == 0) {
            throw new CertificateException("Attribute name not recognized: "
                                           + name);
        }
        // set rawCertInfo to null, so that we are forced to re-encode
        rawCertInfo = null;
        String suffix = attrName.getSuffix();

        switch (attr) {
        case ATTR_VERSION:
            if (suffix == null) {
                version = null;
            } else {
                version.delete(suffix);
            }
            break;
        case (ATTR_SERIAL):
            if (suffix == null) {
                serialNum = null;
            } else {
                serialNum.delete(suffix);
            }
            break;
        case (ATTR_ALGORITHM):
            if (suffix == null) {
                algId = null;
            } else {
                algId.delete(suffix);
            }
            break;
        case (ATTR_ISSUER):
            if (suffix == null) {
                issuer = null;
            } else {
                issuer.delete(suffix);
            }
            break;
        case (ATTR_VALIDITY):
            if (suffix == null) {
                interval = null;
            } else {
                interval.delete(suffix);
            }
            break;
        case (ATTR_SUBJECT):
            if (suffix == null) {
                subject = null;
            } else {
                subject.delete(suffix);
            }
            break;
        case (ATTR_KEY):
            if (suffix == null) {
                pubKey = null;
            } else {
                pubKey.delete(suffix);
            }
            break;
        case (ATTR_ISSUER_ID):
            if (suffix == null) {
                issuerUniqueId = null;
            } else {
                issuerUniqueId.delete(suffix);
            }
            break;
        case (ATTR_SUBJECT_ID):
            if (suffix == null) {
                subjectUniqueId = null;
            } else {
                subjectUniqueId.delete(suffix);
            }
            break;
        case (ATTR_EXTENSIONS):
            if (suffix == null) {
                extensions = null;
            } else {
                if (extensions != null)
                   extensions.delete(suffix);
            }
            break;
        }
    }

    /*
     * Get the certificate attribute.
     *
     * @params name the name of the Certificate attribute.
     *
     * @exception CertificateException on invalid attributes.
     * @exception IOException on other errors.
     */
    public Object get(String name)
    throws CertificateException, IOException {
        X509AttributeName attrName = new X509AttributeName(name);

        int attr = attributeMap(attrName.getPrefix());
        if (attr == 0) {
            throw new CertificateParsingException(
                          "Attribute name not recognized: " + name);
        }
        String suffix = attrName.getSuffix();

        switch (attr) { // frequently used attributes first
        case (ATTR_EXTENSIONS):
            if (suffix == null) {
                return(extensions);
            } else {
                if (extensions == null) {
                    return null;
                } else {
                    return(extensions.get(suffix));
                }
            }
        case (ATTR_SUBJECT):
            if (suffix == null) {
                return(subject);
            } else {
                return(subject.get(suffix));
            }
        case (ATTR_ISSUER):
            if (suffix == null) {
                return(issuer);
            } else {
                return(issuer.get(suffix));
            }
        case (ATTR_KEY):
            if (suffix == null) {
                return(pubKey);
            } else {
                return(pubKey.get(suffix));
            }
        case (ATTR_ALGORITHM):
            if (suffix == null) {
                return(algId);
            } else {
                return(algId.get(suffix));
            }
        case (ATTR_VALIDITY):
            if (suffix == null) {
                return(interval);
            } else {
                return(interval.get(suffix));
            }
        case (ATTR_VERSION):
            if (suffix == null) {
                return(version);
            } else {
                return(version.get(suffix));
            }
        case (ATTR_SERIAL):
            if (suffix == null) {
                return(serialNum);
            } else {
                return(serialNum.get(suffix));
            }
        case (ATTR_ISSUER_ID):
            if (suffix == null) {
                return(issuerUniqueId);
            } else {
                if (issuerUniqueId == null)
                    return null;
                else
                    return(issuerUniqueId.get(suffix));
            }
        case (ATTR_SUBJECT_ID):
            if (suffix == null) {
                return(subjectUniqueId);
            } else {
                if (subjectUniqueId == null)
                    return null;
                else
                    return(subjectUniqueId.get(suffix));
            }
        }
        return null;
    }

    /*
     * This routine unmarshals the certificate information.
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    private void parse(DerValue val)
    throws CertificateParsingException, IOException {
        DerInputStream in;
        DerValue tmp;

        if (val.tag != DerValue.tag_Sequence) {
            throw new CertificateParsingException("signed fields invalid");
        }
        rawCertInfo = val.toByteArray();

        in = val.data;

        // Version
        tmp = in.getDerValue();
        if (tmp.isContextSpecific((byte)0)) {
            version = new CertificateVersion(tmp);
            tmp = in.getDerValue();
        }

        // Serial number ... an integer
        serialNum = new CertificateSerialNumber(tmp);

        // Algorithm Identifier
        algId = new CertificateAlgorithmId(in);

        // Issuer name
        issuer = new CertificateIssuerName(in);
        X500Name issuerDN = (X500Name)issuer.get(CertificateIssuerName.DN_NAME);
        if (issuerDN.isEmpty()) {
            throw new CertificateParsingException(
                "Empty issuer DN not allowed in X509Certificates");
        }

        // validity:  SEQUENCE { start date, end date }
        interval = new CertificateValidity(in);

        // subject name
        subject = new CertificateSubjectName(in);
        X500Name subjectDN = (X500Name)subject.get(CertificateSubjectName.DN_NAME);
        if ((version.compare(CertificateVersion.V1) == 0) &&
                subjectDN.isEmpty()) {
            throw new CertificateParsingException(
                      "Empty subject DN not allowed in v1 certificate");
        }

        // public key
        pubKey = new CertificateX509Key(in);

        // If more data available, make sure version is not v1.
        if (in.available() != 0) {
            if (version.compare(CertificateVersion.V1) == 0) {
                throw new CertificateParsingException(
                          "no more data allowed for version 1 certificate");
            }
        } else {
            return;
        }

        // Get the issuerUniqueId if present
        tmp = in.getDerValue();
        if (tmp.isContextSpecific((byte)1)) {
            issuerUniqueId = new CertificateIssuerUniqueIdentity(tmp);
            if (in.available() == 0)
                return;
            tmp = in.getDerValue();
        }

        // Get the subjectUniqueId if present.
        if (tmp.isContextSpecific((byte)2)) {
            subjectUniqueId = new CertificateSubjectUniqueIdentity(tmp);
            if (in.available() == 0)
                return;
            tmp = in.getDerValue();
        }

        // Get the extensions.
        if (version.compare(CertificateVersion.V3) != 0) {
            throw new CertificateParsingException(
                      "Extensions not allowed in v2 certificate");
        }
        if (tmp.isConstructed() && tmp.isContextSpecific((byte)3)) {
            extensions = new CertificateExtensions(tmp.data);
        }

        // verify X.509 V3 Certificate
        verifyCert(subject, extensions);

    }

    /*
     * Verify if X.509 V3 Certificate is compliant with RFC 3280.
     */
    private void verifyCert(CertificateSubjectName subject,
                            CertificateExtensions extensions)
        throws CertificateParsingException, IOException {

        // if SubjectName is empty, check for SubjectAlternativeNameExtension
        X500Name subjectDN = (X500Name)subject.get(CertificateSubjectName.DN_NAME);
        if (subjectDN.isEmpty()) {
            if (extensions == null) {
                throw new CertificateParsingException("X.509 Certificate is " +
                        "incomplete: subject field is empty, and certificate " +
                        "has no extensions");
            }
            SubjectAlternativeNameExtension subjectAltNameExt;
            GeneralNames names;
            try {
                subjectAltNameExt = (SubjectAlternativeNameExtension)
                        extensions.get(SubjectAlternativeNameExtension.NAME);
                names = (GeneralNames) subjectAltNameExt.get
                        (SubjectAlternativeNameExtension.SUBJECT_NAME);
            } catch (IOException e) {
                throw new CertificateParsingException("X.509 Certificate is " +
                        "incomplete: subject field is empty, and " +
                        "SubjectAlternativeName extension is absent");
            }

            // SubjectAlternativeName extension is empty or not marked critical
            if (names == null || names.isEmpty()) {
                throw new CertificateParsingException("X.509 Certificate is " +
                        "incomplete: subject field is empty, and " +
                        "SubjectAlternativeName extension is empty");
            } else if (!subjectAltNameExt.isCritical()) {
                throw new CertificateParsingException("X.509 Certificate is " +
                        "incomplete: SubjectAlternativeName extension MUST " +
                        "be marked critical when subject field is empty");
            }
        }
    }

    /*
     * Marshal the contents of a "raw" certificate into a DER sequence.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private void emit(DerOutputStream out)
    throws CertificateException, IOException {
        DerOutputStream tmp = new DerOutputStream();

        // version number, iff not V1
        version.encode(tmp);

        // Encode serial number, issuer signing algorithm, issuer name
        // and validity
        serialNum.encode(tmp);
        algId.encode(tmp);

        if ((version.compare(CertificateVersion.V1) == 0)) {
            issuer.toString();
        }

        issuer.encode(tmp);
        interval.encode(tmp);

        // Encode subject (principal) and associated key
        if ((version.compare(CertificateVersion.V1) == 0)) {
            subject.toString();
        }
        subject.encode(tmp);
        pubKey.encode(tmp);

        // Encode issuerUniqueId & subjectUniqueId.
        if (issuerUniqueId != null) {
            issuerUniqueId.encode(tmp);
        }
        if (subjectUniqueId != null) {
            subjectUniqueId.encode(tmp);
        }

        // Write all the extensions.
        if (extensions != null) {
            extensions.encode(tmp);
        }

        // Wrap the data; encoding of the "raw" cert is now complete.
        out.write(DerValue.tag_Sequence, tmp);
    }

    /**
     * Returns the integer attribute number for the passed attribute name.
     */
    private int attributeMap(String name) {
        Integer num = map.get(name);
        if (num == null) {
            return 0;
        }
        return num;
    }

    /*
     * Set the version number of the certificate.
     *
     * @params val the Object class value for the Extensions
     * @exception CertificateException on invalid data.
     */
    private void setVersion(Object val) throws CertificateException {
        if (!(val instanceof CertificateVersion)) {
            throw new CertificateException("Version class type invalid.");
        }
        version = (CertificateVersion)val;
    }

    /*
     * Set the serial number of the certificate.
     *
     * @params val the Object class value for the CertificateSerialNumber
     * @exception CertificateException on invalid data.
     */
    private void setSerialNumber(Object val) throws CertificateException {
        if (!(val instanceof CertificateSerialNumber)) {
            throw new CertificateException("SerialNumber class type invalid.");
        }
        serialNum = (CertificateSerialNumber)val;
    }

    /*
     * Set the algorithm id of the certificate.
     *
     * @params val the Object class value for the AlgorithmId
     * @exception CertificateException on invalid data.
     */
    private void setAlgorithmId(Object val) throws CertificateException {
        if (!(val instanceof CertificateAlgorithmId)) {
            throw new CertificateException(
                             "AlgorithmId class type invalid.");
        }
        algId = (CertificateAlgorithmId)val;
    }

    /*
     * Set the issuer name of the certificate.
     *
     * @params val the Object class value for the issuer
     * @exception CertificateException on invalid data.
     */
    private void setIssuer(Object val) throws CertificateException {
        if (!(val instanceof CertificateIssuerName)) {
            throw new CertificateException(
                             "Issuer class type invalid.");
        }
        issuer = (CertificateIssuerName)val;
    }

    /*
     * Set the validity interval of the certificate.
     *
     * @params val the Object class value for the CertificateValidity
     * @exception CertificateException on invalid data.
     */
    private void setValidity(Object val) throws CertificateException {
        if (!(val instanceof CertificateValidity)) {
            throw new CertificateException(
                             "CertificateValidity class type invalid.");
        }
        interval = (CertificateValidity)val;
    }

    /*
     * Set the subject name of the certificate.
     *
     * @params val the Object class value for the Subject
     * @exception CertificateException on invalid data.
     */
    private void setSubject(Object val) throws CertificateException {
        if (!(val instanceof CertificateSubjectName)) {
            throw new CertificateException(
                             "Subject class type invalid.");
        }
        subject = (CertificateSubjectName)val;
    }

    /*
     * Set the public key in the certificate.
     *
     * @params val the Object class value for the PublicKey
     * @exception CertificateException on invalid data.
     */
    private void setKey(Object val) throws CertificateException {
        if (!(val instanceof CertificateX509Key)) {
            throw new CertificateException(
                             "Key class type invalid.");
        }
        pubKey = (CertificateX509Key)val;
    }

    /*
     * Set the Issuer Unique Identity in the certificate.
     *
     * @params val the Object class value for the IssuerUniqueId
     * @exception CertificateException
     */
    private void setIssuerUniqueId(Object val) throws CertificateException {
        if (version.compare(CertificateVersion.V2) < 0) {
            throw new CertificateException("Invalid version");
        }
        if (!(val instanceof CertificateIssuerUniqueIdentity)) {
            throw new CertificateException(
                             "IssuerUniqueId class type invalid.");
        }
        issuerUniqueId = (CertificateIssuerUniqueIdentity)val;
    }

    /*
     * Set the Subject Unique Identity in the certificate.
     *
     * @params val the Object class value for the SubjectUniqueId
     * @exception CertificateException
     */
    private void setSubjectUniqueId(Object val) throws CertificateException {
        if (version.compare(CertificateVersion.V2) < 0) {
            throw new CertificateException("Invalid version");
        }
        if (!(val instanceof CertificateSubjectUniqueIdentity)) {
            throw new CertificateException(
                             "SubjectUniqueId class type invalid.");
        }
        subjectUniqueId = (CertificateSubjectUniqueIdentity)val;
    }

    /*
     * Set the extensions in the certificate.
     *
     * @params val the Object class value for the Extensions
     * @exception CertificateException
     */
    private void setExtensions(Object val) throws CertificateException {
        if (version.compare(CertificateVersion.V3) < 0) {
            throw new CertificateException("Invalid version");
        }
        if (!(val instanceof CertificateExtensions)) {
          throw new CertificateException(
                             "Extensions class type invalid.");
        }
        extensions = (CertificateExtensions)val;
    }
}