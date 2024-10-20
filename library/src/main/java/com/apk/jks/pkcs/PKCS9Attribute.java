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

import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.CertificateException;
import java.util.Locale;
import java.util.Date;
import java.util.Hashtable;
import java.util.Objects;

import com.apk.jks.x509.CertificateExtensions;
import com.apk.jks.utils.Debug;
import com.apk.jks.utils.DerEncoder;
import com.apk.jks.utils.DerValue;
import com.apk.jks.utils.DerInputStream;
import com.apk.jks.utils.DerOutputStream;
import com.apk.jks.utils.ObjectIdentifier;
import com.apk.jks.utils.HexDumpEncoder;

import androidx.annotation.NonNull;

public class PKCS9Attribute implements DerEncoder {

    /* Are we debugging ? */
    private static final Debug debug = Debug.getInstance("jar");

    /**
     * Array of attribute OIDs defined in PKCS9, by number.
     */
    static final ObjectIdentifier[] PKCS9_OIDS = new ObjectIdentifier[18];

    static {   // static initializer for PKCS9_OIDS
        for (int i = 1; i < PKCS9_OIDS.length - 2; i++) {
            PKCS9_OIDS[i] =
                ObjectIdentifier.newInternal(new int[]{1,2,840,113549,1,9,i});
        }
        // Initialize SigningCertificate and SignatureTimestampToken
        // separately (because their values are out of sequence)
        PKCS9_OIDS[PKCS9_OIDS.length - 2] =
            ObjectIdentifier.newInternal(new int[]{1,2,840,113549,1,9,16,2,12});
        PKCS9_OIDS[PKCS9_OIDS.length - 1] =
            ObjectIdentifier.newInternal(new int[]{1,2,840,113549,1,9,16,2,14});
    }

    // first element [0] not used
    public static final ObjectIdentifier EMAIL_ADDRESS_OID = PKCS9_OIDS[1];
    public static final ObjectIdentifier CONTENT_TYPE_OID = PKCS9_OIDS[3];
    public static final ObjectIdentifier MESSAGE_DIGEST_OID = PKCS9_OIDS[4];
    public static final String EMAIL_ADDRESS_STR = "EmailAddress";
    public static final String UNSTRUCTURED_NAME_STR = "UnstructuredName";
    public static final String CONTENT_TYPE_STR = "ContentType";
    public static final String MESSAGE_DIGEST_STR = "MessageDigest";
    public static final String SIGNING_TIME_STR = "SigningTime";
    public static final String COUNTERSIGNATURE_STR = "Countersignature";
    public static final String CHALLENGE_PASSWORD_STR = "ChallengePassword";
    public static final String UNSTRUCTURED_ADDRESS_STR = "UnstructuredAddress";
    public static final String EXTENDED_CERTIFICATE_ATTRIBUTES_STR =
                               "ExtendedCertificateAttributes";
    public static final String ISSUER_SERIALNUMBER_STR = "IssuerAndSerialNumber";
    // [11], [12] are RSA DSI proprietary
    private static final String RSA_PROPRIETARY_STR = "RSAProprietary";
    // [13] ==> signingDescription, S/MIME, not used anymore
    private static final String SMIME_SIGNING_DESC_STR = "SMIMESigningDesc";
    public static final String EXTENSION_REQUEST_STR = "ExtensionRequest";
    public static final String SMIME_CAPABILITY_STR = "SMIMECapability";
    public static final String SIGNING_CERTIFICATE_STR = "SigningCertificate";
    public static final String SIGNATURE_TIMESTAMP_TOKEN_STR =
                                "SignatureTimestampToken";

    /**
     * Hashtable mapping names and variant names of supported
     * attributes to their OIDs. This table contains all name forms
     * that occur in PKCS9, in lower case.
     */
    private static final Hashtable<String, ObjectIdentifier> NAME_OID_TABLE =
            new Hashtable<>(18);

    static { // static initializer for PCKS9_NAMES
        NAME_OID_TABLE.put("emailaddress", PKCS9_OIDS[1]);
        NAME_OID_TABLE.put("unstructuredname", PKCS9_OIDS[2]);
        NAME_OID_TABLE.put("contenttype", PKCS9_OIDS[3]);
        NAME_OID_TABLE.put("messagedigest", PKCS9_OIDS[4]);
        NAME_OID_TABLE.put("signingtime", PKCS9_OIDS[5]);
        NAME_OID_TABLE.put("countersignature", PKCS9_OIDS[6]);
        NAME_OID_TABLE.put("challengepassword", PKCS9_OIDS[7]);
        NAME_OID_TABLE.put("unstructuredaddress", PKCS9_OIDS[8]);
        NAME_OID_TABLE.put("extendedcertificateattributes", PKCS9_OIDS[9]);
        NAME_OID_TABLE.put("issuerandserialnumber", PKCS9_OIDS[10]);
        NAME_OID_TABLE.put("rsaproprietary", PKCS9_OIDS[11]);
        NAME_OID_TABLE.put("signingdescription", PKCS9_OIDS[12]);
        NAME_OID_TABLE.put("extensionrequest", PKCS9_OIDS[13]);
        NAME_OID_TABLE.put("smimecapability", PKCS9_OIDS[14]);
        NAME_OID_TABLE.put("signingcertificate", PKCS9_OIDS[15]);
        NAME_OID_TABLE.put("signaturetimestamptoken", PKCS9_OIDS[16]);
    }

    /**
     * Hashtable mapping attribute OIDs defined in PKCS9 to the
     * corresponding attribute value type.
     */
    private static final Hashtable<ObjectIdentifier, String> OID_NAME_TABLE =
            new Hashtable<>(16);
    static {
        OID_NAME_TABLE.put(PKCS9_OIDS[1], EMAIL_ADDRESS_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[2], UNSTRUCTURED_NAME_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[3], CONTENT_TYPE_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[4], MESSAGE_DIGEST_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[5], SIGNING_TIME_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[6], COUNTERSIGNATURE_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[7], CHALLENGE_PASSWORD_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[8], UNSTRUCTURED_ADDRESS_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[9], EXTENDED_CERTIFICATE_ATTRIBUTES_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[10], ISSUER_SERIALNUMBER_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[11], RSA_PROPRIETARY_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[12], RSA_PROPRIETARY_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[13], SMIME_SIGNING_DESC_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[14], EXTENSION_REQUEST_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[15], SMIME_CAPABILITY_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[16], SIGNING_CERTIFICATE_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[17], SIGNATURE_TIMESTAMP_TOKEN_STR);
    }

    /**
     * Acceptable ASN.1 tags for DER encodings of values of PKCS9
     * attributes, by index in <code>PKCS9_OIDS</code>.
     * Sets of acceptable tags are represented as arrays.
     */
    private static final Byte[][] PKCS9_VALUE_TAGS = {
            null,
            {DerValue.tag_IA5String},   // EMailAddress
            {DerValue.tag_IA5String},   // UnstructuredName
            {DerValue.tag_ObjectId},    // ContentType
            {DerValue.tag_OctetString}, // MessageDigest
            {DerValue.tag_UtcTime},     // SigningTime
            {DerValue.tag_Sequence},    // Countersignature
            {DerValue.tag_PrintableString,
                    DerValue.tag_T61String},   // ChallengePassword
            {DerValue.tag_PrintableString,
                    DerValue.tag_T61String},   // UnstructuredAddress
            {DerValue.tag_SetOf},       // ExtendedCertificateAttributes
            {DerValue.tag_Sequence},    // issuerAndSerialNumber
            null,
            null,
            null,
            {DerValue.tag_Sequence},    // extensionRequest
            {DerValue.tag_Sequence},    // SMIMECapability
            {DerValue.tag_Sequence},    // SigningCertificate
            {DerValue.tag_Sequence}     // SignatureTimestampToken
    };

    private static final Class[] VALUE_CLASSES = new Class[18];

    static {
        try {
            Class str = Class.forName("[Ljava.lang.String;");

            VALUE_CLASSES[0] = null;  // not used
            VALUE_CLASSES[1] = str;   // EMailAddress
            VALUE_CLASSES[2] = str;   // UnstructuredName
            VALUE_CLASSES[3] = ObjectIdentifier.class; // ContentType
            VALUE_CLASSES[4] = Class.forName("[B"); // MessageDigest (byte[])
            VALUE_CLASSES[5] = Class.forName("java.util.Date"); // SigningTime
            VALUE_CLASSES[6] =        // Countersignature
                    Class.forName("[L" + SignerInfo.class.getName() + ";");
            VALUE_CLASSES[7] =        // ChallengePassword
                Class.forName("java.lang.String");
            VALUE_CLASSES[8] = str;   // UnstructuredAddress
            VALUE_CLASSES[9] = null;  // ExtendedCertificateAttributes
            VALUE_CLASSES[10] = null;  // IssuerAndSerialNumber
            VALUE_CLASSES[11] = null;  // not used
            VALUE_CLASSES[12] = null;  // not used
            VALUE_CLASSES[13] = null;  // not used
            VALUE_CLASSES[14] = CertificateExtensions.class; // ExtensionRequest
            VALUE_CLASSES[15] = null;  // not supported yet
            VALUE_CLASSES[16] = null;  // not supported yet
            VALUE_CLASSES[17] = Class.forName("[B");  // SignatureTimestampToken
        } catch (ClassNotFoundException e) {
            throw new ExceptionInInitializerError(e.toString());
        }
    }

    /**
     * Array indicating which PKCS9 attributes are single-valued,
     * by index in <code>PKCS9_OIDS</code>.
     */
    private static final boolean[] SINGLE_VALUED = {
      false,
      false,   // EMailAddress
      false,   // UnstructuredName
      true,    // ContentType
      true,    // MessageDigest
      true,    // SigningTime
      false,   // Countersignature
      true,    // ChallengePassword
      false,   // UnstructuredAddress
      false,   // ExtendedCertificateAttributes
      true,    // IssuerAndSerialNumber - not supported yet
      false,   // not used
      false,   // not used
      false,   // not used
      true,    // ExtensionRequest
      true,    // SMIMECapability - not supported yet
      true,    // SigningCertificate
      true     // SignatureTimestampToken
    };

    /**
     * The OID of this attribute is <code>PKCS9_OIDS[index]</code>.
     */
    private final int index;

    /**
     * Value set of this attribute.  Its class is given by
     * <code>VALUE_CLASSES[index]</code>.
     */
    private Object value;


    /**
     * Construct a PKCS9Attribute from its encoding on an input
     * stream.
     *
     * @param derVal the DerValue representing the DER encoding of the attribute.
     * @exception IOException on parsing error.
     */
    public PKCS9Attribute(DerValue derVal) throws IOException {

        DerInputStream derIn = new DerInputStream(derVal.toByteArray());
        DerValue[] val =  derIn.getSequence(2);

        if (derIn.available() != 0)
            throw new IOException("Excess data parsing PKCS9Attribute");

        if (val.length != 2)
            throw new IOException("PKCS9Attribute doesn't have two components");

        // get the oid
        ObjectIdentifier oid = val[0].getOID();
        index = indexOf(oid, PKCS9_OIDS, 1);
        if (index == -1) {
            if (debug != null) {
                debug.println("ignoring unsupported signer attribute: " + oid);
            }
            throw new ParsingException("Unsupported PKCS9 attribute: " + oid);
        }

        DerValue[] elems = new DerInputStream(val[1].toByteArray()).getSet(1);
        // check single valued have only one value
        if (SINGLE_VALUED[index] && elems.length > 1)
            throwSingleValuedException();

        // check for illegal element tags
        Byte tag;
        for (DerValue elem : elems) {
            tag = elem.tag;

            if (indexOf(tag, Objects.requireNonNull(PKCS9_VALUE_TAGS[index]), 0) == -1)
                throwTagException(tag);
        }

        switch (index) {
        case 1:     // email address
        case 2:     // unstructured name
        case 8:     // unstructured address
            { // open scope
                String[] values = new String[elems.length];

                for (int i=0; i < elems.length; i++)
                    values[i] = elems[i].getAsString();
                value = values;
            } // close scope
            break;

        case 3:     // content type
            value = elems[0].getOID();
            break;

        case 4:     // message digest
            value = elems[0].getOctetString();
            break;

        case 5:     // signing time
            value = (new DerInputStream(elems[0].toByteArray())).getUTCTime();
            break;

        case 6:     // countersignature
            { // open scope
                SignerInfo[] values = new SignerInfo[elems.length];
                for (int i=0; i < elems.length; i++)
                    values[i] =
                        new SignerInfo(elems[i].toDerInputStream());
                value = values;
            } // close scope
            break;

        case 7:     // challenge password
            value = elems[0].getAsString();
            break;

        case 9:     // extended-certificate attribute -- not supported
            throw new IOException("PKCS9 extended-certificate " +
                                  "attribute not supported.");
            // break unnecessary
        case 10:    // issuerAndserialNumber attribute -- not supported
            throw new IOException("PKCS9 IssuerAndSerialNumber" +
                                  "attribute not supported.");
            // break unnecessary
        case 11:    // RSA DSI proprietary
        case 12:    // RSA DSI proprietary
            throw new IOException("PKCS9 RSA DSI attributes" +
                                  "11 and 12, not supported.");
            // break unnecessary
        case 13:    // S/MIME unused attribute
            throw new IOException("PKCS9 attribute #13 not supported.");
            // break unnecessary

        case 14:     // ExtensionRequest
            value = new CertificateExtensions(
                       new DerInputStream(elems[0].toByteArray()));
            break;

        case 15:     // SMIME-capability attribute -- not supported
            throw new IOException("PKCS9 SMIMECapability " +
                                  "attribute not supported.");
            // break unnecessary
        case 16:     // SigningCertificate attribute
            value = new SigningCertificateInfo(elems[0].toByteArray());
            break;

        case 17:     // SignatureTimestampToken attribute
            value = elems[0].toByteArray();
            break;
        default: // can't happen
        }
    }

    /**
     * Write the DER encoding of this attribute to an output stream.
     *
     * <P> N.B.: This method always encodes values of
     * ChallengePassword and UnstructuredAddress attributes as ASN.1
     * <code>PrintableString</code>s, without checking whether they
     * should be encoded as <code>T61String</code>s.
     */
    public void derEncode(OutputStream out) throws IOException {
        DerOutputStream temp = new DerOutputStream();
        temp.putOID(getOID());
        switch (index) {
        case 1:     // email address
        case 2:     // unstructured name
            { // open scope
                String[] values = (String[]) value;
                DerOutputStream[] temps = new
                    DerOutputStream[values.length];

                for (int i=0; i < values.length; i++) {
                    temps[i] = new DerOutputStream();
                    temps[i].putIA5String( values[i]);
                }
                temp.putOrderedSetOf(DerValue.tag_Set, temps);
            } // close scope
            break;

        case 3:     // content type
            {
                DerOutputStream temp2 = new DerOutputStream();
                temp2.putOID((ObjectIdentifier) value);
                temp.write(DerValue.tag_Set, temp2.toByteArray());
            }
            break;

        case 4:     // message digest
            {
                DerOutputStream temp2 = new DerOutputStream();
                temp2.putOctetString((byte[]) value);
                temp.write(DerValue.tag_Set, temp2.toByteArray());
            }
            break;

        case 5:     // signing time
            {
                DerOutputStream temp2 = new DerOutputStream();
                temp2.putUTCTime((Date) value);
                temp.write(DerValue.tag_Set, temp2.toByteArray());
            }
            break;

        case 6:     // countersignature
            temp.putOrderedSetOf(DerValue.tag_Set, (DerEncoder[]) value);
            break;

        case 7:     // challenge password
            {
                DerOutputStream temp2 = new DerOutputStream();
                temp2.putPrintableString((String) value);
                temp.write(DerValue.tag_Set, temp2.toByteArray());
            }
            break;

        case 8:     // unstructured address
            { // open scope
                String[] values = (String[]) value;
                DerOutputStream[] temps = new
                    DerOutputStream[values.length];

                for (int i=0; i < values.length; i++) {
                    temps[i] = new DerOutputStream();
                    temps[i].putPrintableString(values[i]);
                }
                temp.putOrderedSetOf(DerValue.tag_Set, temps);
            } // close scope
            break;

        case 9:     // extended-certificate attribute -- not supported
            throw new IOException("PKCS9 extended-certificate " +
                                  "attribute not supported.");
            // break unnecessary
        case 10:    // issuerAndserialNumber attribute -- not supported
            throw new IOException("PKCS9 IssuerAndSerialNumber" +
                                  "attribute not supported.");
            // break unnecessary
        case 11:    // RSA DSI proprietary
        case 12:    // RSA DSI proprietary
            throw new IOException("PKCS9 RSA DSI attributes" +
                                  "11 and 12, not supported.");
            // break unnecessary
        case 13:    // S/MIME unused attribute
            throw new IOException("PKCS9 attribute #13 not supported.");
            // break unnecessary

        case 14:     // ExtensionRequest
            {
                DerOutputStream temp2 = new DerOutputStream();
                CertificateExtensions exts = (CertificateExtensions)value;
                try {
                    exts.encode(temp2, true);
                } catch (CertificateException ex) {
                    throw new IOException(ex.toString());
                }
                temp.write(DerValue.tag_Set, temp2.toByteArray());
            }
            break;
        case 15:    // SMIMECapability
            throw new IOException("PKCS9 attribute #15 not supported.");
            // break unnecessary

        case 16:    // SigningCertificate
            throw new IOException(
                "PKCS9 SigningCertificate attribute not supported.");
            // break unnecessary

        case 17:    // SignatureTimestampToken
            temp.write(DerValue.tag_Set, (byte[])value);
            break;

        default: // can't happen
        }

        DerOutputStream derOut = new DerOutputStream();
        derOut.write(DerValue.tag_Sequence, temp.toByteArray());

        out.write(derOut.toByteArray());

    }

    /**
     * Get the value of this attribute.  If the attribute is
     * single-valued, return just the one value.  If the attribute is
     * multi-valued, return an array containing all the values.
     * It is possible for this array to be of length 0.
     *
     * <P> The
     * <a href=#classTable>table</a> gives the class of the value returned,
     * depending on the type of this attribute.
     */
    public Object getValue() {
        return value;
    }

    /**
     *  Return the OID of this attribute.
     */
    public ObjectIdentifier getOID() {
        return PKCS9_OIDS[index];
    }

    /**
     *  Return the name of this attribute.
     */
    public String getName() {
        return OID_NAME_TABLE.get(PKCS9_OIDS[index]);
    }

    /**
     * Return the OID for a given attribute name or null if we don't recognize
     * the name.
     */
    public static ObjectIdentifier getOID(String name) {
        return NAME_OID_TABLE.get(name.toLowerCase(Locale.ENGLISH));
    }

    /**
     * Return the attribute name for a given OID or null if we don't recognize
     * the oid.
     */
    public static String getName(ObjectIdentifier oid) {
        return OID_NAME_TABLE.get(oid);
    }

    /**
     * Returns a string representation of this attribute.
     */
    @NonNull
    public String toString() {
        StringBuilder buf = new StringBuilder(100);

        buf.append("[");

        buf.append(OID_NAME_TABLE.get(PKCS9_OIDS[index]));
        buf.append(": ");

        if (SINGLE_VALUED[index]) {
            if (value instanceof byte[]) { // special case for octet string
                HexDumpEncoder hexDump = new HexDumpEncoder();
                buf.append(hexDump.encodeBuffer((byte[]) value));
            } else {
                buf.append(value.toString());
            }
            buf.append("]");
        } else { // multi-valued
            boolean first = true;
            Object[] values = (Object[]) value;

            for (Object o : values) {
                if (first)
                    first = false;
                else
                    buf.append(", ");

                buf.append(o.toString());
            }
        }
        return buf.toString();
    }

    /**
     * Beginning the search at <code>start</code>, find the first
     * index <code>i</code> such that <code>a[i] = obj</code>.
     *
     * @return the index, if found, and -1 otherwise.
     */
    static int indexOf(Object obj, Object[] a, int start) {
        for (int i=start; i < a.length; i++) {
            if (obj.equals(a[i])) return i;
        }
        return -1;
    }

    /**
     * Throw an exception when there are multiple values for
     * a single-valued attribute.
     */
    private void throwSingleValuedException() throws IOException {
        throw new IOException("Single-value attribute " +
                              getOID() + " (" + getName() + ")" +
                              " has multiple values.");
    }

    /**
     * Throw an exception when the tag on a value encoding is
     * wrong for the attribute whose value it is.
     */
    private void throwTagException(Byte tag)
    throws IOException {
        Byte[] expectedTags = PKCS9_VALUE_TAGS[index];
        StringBuilder msg = new StringBuilder(100);
        msg.append("Value of attribute ");
        msg.append(getOID().toString());
        msg.append(" (");
        msg.append(getName());
        msg.append(") has wrong tag: ");
        msg.append(tag.toString());
        msg.append(".  Expected tags: ");

        if (expectedTags != null) {
            msg.append(expectedTags[0].toString());

            for (int i = 1; i < expectedTags.length; i++) {
                msg.append(", ");
                msg.append(expectedTags[i].toString());
            }
        }
        msg.append(".");
        throw new IOException(msg.toString());
    }
}