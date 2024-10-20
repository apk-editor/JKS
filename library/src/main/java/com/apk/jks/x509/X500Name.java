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

import com.apk.jks.utils.DerInputStream;
import com.apk.jks.utils.DerOutputStream;
import com.apk.jks.utils.DerValue;
import com.apk.jks.utils.ObjectIdentifier;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

public class X500Name implements GeneralNameInterface, Principal {
    private String dn; // roughly RFC 1779 DN, or null
    private String rfc2253Dn; // RFC 2253 DN, or null
    private String canonicalDn; // canonical RFC 2253 DN or null
    private RDN[] names;        // RDNs (never null)
    private X500Principal x500Principal;
    private byte[] encoded;

    /**
     * Constructs a name from a conventionally formatted string, such
     * as "CN=Dave, OU=JavaSoft, O=Sun Microsystems, C=US".
     * (RFC 1779 or RFC 2253 style).
     *
     * @param dname X.500 Distinguished Name
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public X500Name(String dname) throws IOException {
        this(dname, Collections.emptyMap());
    }

    /**
     * Constructs a name from a conventionally formatted string, such
     * as "CN=Dave, OU=JavaSoft, O=Sun Microsystems, C=US".
     * (RFC 1779 or RFC 2253 style).
     *
     * @param dname      X.500 Distinguished Name
     * @param keywordMap an additional keyword/OID map
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public X500Name(String dname, Map<String, String> keywordMap) throws IOException {
        parseDN(dname, keywordMap);
    }

    /**
     * Constructs a name from a string formatted according to format.
     * Currently, the formats DEFAULT and RFC2253 are supported.
     * DEFAULT is the default format used by the X500Name(String)
     * constructor. RFC2253 is format strictly according to RFC2253
     * without extensions.
     *
     * @param dname X.500 Distinguished Name
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public X500Name(String dname, String format) throws IOException {
        if (dname == null) {
            throw new NullPointerException("Name must not be null");
        }
        if (format.equalsIgnoreCase("RFC2253")) {
            parseRFC2253DN(dname);
        } else if (format.equalsIgnoreCase("DEFAULT")) {
            parseDN(dname, Collections.emptyMap());
        } else {
            throw new IOException("Unsupported format " + format);
        }
    }

    /**
     * Constructs a name from fields common in enterprise application
     * environments.
     *
     * <P><EM><STRONG>NOTE:</STRONG>  The behaviour when any of
     * these strings contain characters outside the ASCII range
     * is unspecified in currently relevant standards.</EM>
     *
     * @param commonName       common name of a person, e.g. "Vivette Davis"
     * @param organizationUnit small organization name, e.g. "Purchasing"
     * @param organizationName large organization name, e.g. "Onizuka, Inc."
     * @param country          two letter country code, e.g. "CH"
     */
    public X500Name(String commonName, String organizationUnit, String organizationName, String country)
            throws IOException {
        names = new RDN[4];
        /*
         * NOTE:  it's only on output that little-endian
         * ordering is used.
         */
        names[3] = new RDN(1);
        names[3].assertion[0] = new AVA(commonName_oid, new DerValue(commonName));
        names[2] = new RDN(1);
        names[2].assertion[0] = new AVA(orgUnitName_oid, new DerValue(organizationUnit));
        names[1] = new RDN(1);
        names[1].assertion[0] = new AVA(orgName_oid, new DerValue(organizationName));
        names[0] = new RDN(1);
        names[0].assertion[0] = new AVA(countryName_oid, new DerValue(country));
    }

    /**
     * Constructs a name from fields common in Internet application
     * environments.
     *
     * <P><EM><STRONG>NOTE:</STRONG>  The behaviour when any of
     * these strings contain characters outside the ASCII range
     * is unspecified in currently relevant standards.</EM>
     *
     * @param commonName       common name of a person, e.g. "Vivette Davis"
     * @param organizationUnit small organization name, e.g. "Purchasing"
     * @param organizationName large organization name, e.g. "Onizuka, Inc."
     * @param localityName     locality (city) name, e.g. "Palo Alto"
     * @param stateName        state name, e.g. "California"
     * @param country          two letter country code, e.g. "CH"
     */
    public X500Name(String commonName, String organizationUnit, String organizationName, String localityName,
                    String stateName, String country)
            throws IOException {
        names = new RDN[6];
        /*
         * NOTE:  it's only on output that little-endian
         * ordering is used.
         */
        names[5] = new RDN(1);
        names[5].assertion[0] = new AVA(commonName_oid, new DerValue(commonName));
        names[4] = new RDN(1);
        names[4].assertion[0] = new AVA(orgUnitName_oid, new DerValue(organizationUnit));
        names[3] = new RDN(1);
        names[3].assertion[0] = new AVA(orgName_oid, new DerValue(organizationName));
        names[2] = new RDN(1);
        names[2].assertion[0] = new AVA(localityName_oid, new DerValue(localityName));
        names[1] = new RDN(1);
        names[1].assertion[0] = new AVA(stateName_oid, new DerValue(stateName));
        names[0] = new RDN(1);
        names[0].assertion[0] = new AVA(countryName_oid, new DerValue(country));
    }

    /**
     * Constructs a name from an array of relative distinguished names
     *
     * @param rdnArray array of relative distinguished names
     * @throws IOException on error
     */
    public X500Name(RDN[] rdnArray) throws IOException {
        if (rdnArray == null) {
            names = new RDN[0];
        } else {
            names = rdnArray.clone();
            for (RDN name : names) {
                if (name == null) {
                    throw new IOException("Cannot create an X500Name");
                }
            }
        }
    }

    /**
     * Constructs a name from an ASN.1 encoded value.  The encoding
     * of the name in the stream uses DER (a BER/1 subset).
     *
     * @param value a DER-encoded value holding an X.500 name.
     */
    public X500Name(DerValue value) throws IOException {
        //Note that toDerInputStream uses only the buffer (data) and not
        //the tag, so an empty SEQUENCE (OF) will yield an empty DerInputStream
        this(value.toDerInputStream());
    }

    /**
     * Constructs a name from an ASN.1 encoded input stream.  The encoding
     * of the name in the stream uses DER (a BER/1 subset).
     *
     * @param in DER-encoded data holding an X.500 name.
     */
    public X500Name(DerInputStream in) throws IOException {
        parseDER(in);
    }

    /**
     * Constructs a name from an ASN.1 encoded byte array.
     *
     * @param name DER-encoded byte array holding an X.500 name.
     */
    public X500Name(byte[] name) throws IOException {
        DerInputStream in = new DerInputStream(name);
        parseDER(in);
    }

    /**
     * Return the number of RDNs in this X500Name.
     */
    public int size() {
        return names.length;
    }

    /**
     * Return whether this X500Name is empty. An X500Name is not empty
     * if it has at least one RDN containing at least one AVA.
     */
    public boolean isEmpty() {
        int n = names.length;
        if (n == 0) {
            return true;
        }
        for (RDN name : names) {
            if (name.assertion.length != 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Calculates a hash code value for the object.  Objects
     * which are equal will also have the same hashcode.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public int hashCode() {
        return getRFC2253CanonicalName().hashCode();
    }

    /**
     * Compares this name with another, for equality.
     *
     * @return true iff the names are identical.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof X500Name)) {
            return false;
        }
        X500Name other = (X500Name) obj;
        // if we already have the canonical forms, compare now
        if ((this.canonicalDn != null) && (other.canonicalDn != null)) {
            return this.canonicalDn.equals(other.canonicalDn);
        }
        // quick check that number of RDNs and AVAs match before canonicalizing
        int n = this.names.length;
        if (n != other.names.length) {
            return false;
        }
        for (int i = 0; i < n; i++) {
            RDN r1 = this.names[i];
            RDN r2 = other.names[i];
            if (r1.assertion.length != r2.assertion.length) {
                return false;
            }
        }
        // definite check via canonical form
        String thisCanonical = this.getRFC2253CanonicalName();
        String otherCanonical = other.getRFC2253CanonicalName();
        return thisCanonical.equals(otherCanonical);
    }

    /**
     * Return type of GeneralName.
     */
    public int getType() {
        return NAME_DIRECTORY;
    }

    /**
     * Returns a string form of the X.500 distinguished name.
     * The format of the string is from RFC 1779. The returned string
     * may contain non-standardised keywords for more readability
     * (keywords from RFCs 1779, 2253, and 3280).
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    @NonNull
    public String toString() {
        if (dn == null) {
            generateDN();
        }
        return dn;
    }

    /**
     * Returns a string form of the X.500 distinguished name
     * using the algorithm defined in RFC 2253. Only standard attribute type
     * keywords defined in RFC 2253 are emitted.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public String getRFC2253Name() {
        return getRFC2253Name(Collections.emptyMap());
    }

    /**
     * Returns a string form of the X.500 distinguished name
     * using the algorithm defined in RFC 2253. Attribute type
     * keywords defined in RFC 2253 are emitted, as well as additional
     * keywords contained in the OID/keyword map.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public String getRFC2253Name(Map<String, String> oidMap) {
        /* check for and return cached name */
        if (oidMap.isEmpty()) {
            if (rfc2253Dn == null) {
                rfc2253Dn = generateRFC2253DN(oidMap);
            }
            return rfc2253Dn;
        }
        return generateRFC2253DN(oidMap);
    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private String generateRFC2253DN(Map<String, String> oidMap) {
        /*
         * Section 2.1 : if the RDNSequence is an empty sequence
         * the result is the empty or zero length string.
         */
        if (names.length == 0) {
            return "";
        }

        /*
         * 2.1 (continued) : Otherwise, the output consists of the string
         * encodings of each RelativeDistinguishedName in the RDNSequence
         * (according to 2.2), starting with the last element of the sequence
         * and moving backwards toward the first.
         *
         * The encodings of adjoining RelativeDistinguishedNames are separated
         * by a comma character (',' ASCII 44).
         */
        StringBuilder fullname = new StringBuilder(48);
        for (int i = names.length - 1; i >= 0; i--) {
            if (i < names.length - 1) {
                fullname.append(',');
            }
            fullname.append(names[i].toRFC2253String(oidMap));
        }
        return fullname.toString();
    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public String getRFC2253CanonicalName() {
        /* check for and return cached name */
        if (canonicalDn != null) {
            return canonicalDn;
        }
        /*
         * Section 2.1 : if the RDNSequence is an empty sequence
         * the result is the empty or zero length string.
         */
        if (names.length == 0) {
            canonicalDn = "";
            return canonicalDn;
        }

        /*
         * 2.1 (continued) : Otherwise, the output consists of the string
         * encodings of each RelativeDistinguishedName in the RDNSequence
         * (according to 2.2), starting with the last element of the sequence
         * and moving backwards toward the first.
         *
         * The encodings of adjoining RelativeDistinguishedNames are separated
         * by a comma character (',' ASCII 44).
         */
        StringBuilder fullname = new StringBuilder(48);
        for (int i = names.length - 1; i >= 0; i--) {
            if (i < names.length - 1) {
                fullname.append(',');
            }
            fullname.append(names[i].toRFC2253String(true));
        }
        canonicalDn = fullname.toString();
        return canonicalDn;
    }

    /**
     * Returns the value of toString().  This call is needed to
     * implement the java.security.Principal interface.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public String getName() {
        return toString();
    }

    private void parseDER(DerInputStream in) throws IOException {
        //
        // X.500 names are a "SEQUENCE OF" RDNs, which means zero or
        // more and order matters.  We scan them in order, which
        // conventionally is big-endian.
        //
        DerValue[] nameseq;
        byte[] derBytes = in.toByteArray();

        try {
            nameseq = in.getSequence(5);
        } catch (IOException ioe) {
            if (derBytes == null) {
                nameseq = null;
            } else {
                DerValue derVal = new DerValue(DerValue.tag_Sequence,
                        derBytes);
                derBytes = derVal.toByteArray();
                nameseq = new DerInputStream(derBytes).getSequence(5);
            }
        }

        if (nameseq == null) {
            names = new RDN[0];
        } else {
            names = new RDN[nameseq.length];
            for (int i = 0; i < nameseq.length; i++) {
                names[i] = new RDN(nameseq[i]);
            }
        }
    }

    /**
     * Encodes the name in DER-encoded form.
     *
     * @param out where to put the DER-encoded X.500 name
     * @deprecated Use encode() instead
     */
    @Deprecated
    public void emit(DerOutputStream out) throws IOException {
        encode(out);
    }

    /**
     * Encodes the name in DER-encoded form.
     *
     * @param out where to put the DER-encoded X.500 name
     */
    public void encode(DerOutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        for (RDN name : names) {
            name.encode(tmp);
        }
        out.write(DerValue.tag_Sequence, tmp);
    }

    /**
     * Returned the encoding as an uncloned byte array. Callers must
     * guarantee that they neither modify it not expose it to untrusted
     * code.
     */
    public byte[] getEncodedInternal() throws IOException {
        if (encoded == null) {
            DerOutputStream out = new DerOutputStream();
            DerOutputStream tmp = new DerOutputStream();
            for (RDN name : names) {
                name.encode(tmp);
            }
            out.write(DerValue.tag_Sequence, tmp);
            encoded = out.toByteArray();
        }
        return encoded;
    }

    /**
     * Gets the name in DER-encoded form.
     *
     * @return the DER encoded byte array of this name.
     */
    public byte[] getEncoded() throws IOException {
        return getEncodedInternal().clone();
    }

    /*
     * Parses a Distinguished Name (DN) in printable representation.
     *
     * According to RFC 1779, RDNs in a DN are separated by comma.
     * The following examples show both methods of quoting a comma, so that it
     * is not considered a separator:
     *
     *     O="Sue, Grabbit and Runn" or
     *     O=Sue\, Grabbit and Runn
     *
     * This method can parse 1779 or 2253 DNs and non-standard 3280 keywords.
     * Additional keywords can be specified in the keyword/OID map.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private void parseDN(String dname, Map<String, String> keywordMap)
            throws IOException {
        if (dname == null || dname.isEmpty()) {
            names = new RDN[0];
            return;
        }

        this.x500Principal = new X500Principal(dname, keywordMap);
        List<RDN> dnVector = new ArrayList<>();
        int dnOffset = 0;
        int rdnEnd;
        String rdnString;
        int quoteCount = 0;

        int searchOffset = 0;
        int nextComma = dname.indexOf(',');
        int nextSemiColon = dname.indexOf(';');
        while (nextComma >= 0 || nextSemiColon >= 0) {
            if (nextSemiColon < 0) {
                rdnEnd = nextComma;
            } else if (nextComma < 0) {
                rdnEnd = nextSemiColon;
            } else {
                rdnEnd = Math.min(nextComma, nextSemiColon);
            }
            quoteCount += countQuotes(dname, searchOffset, rdnEnd);

            /*
             * We have encountered an RDN delimiter (comma or a semicolon).
             * If the comma or semicolon in the RDN under consideration is
             * preceded by a backslash (escape), or by a double quote, it
             * is part of the RDN. Otherwise, it is used as a separator, to
             * delimit the RDN under consideration from any subsequent RDNs.
             */
            if (quoteCount != 1 && !escaped(rdnEnd, searchOffset, dname)) {
                /*
                 * Comma/semicolon is a separator
                 */
                rdnString = dname.substring(dnOffset, rdnEnd);

                // Parse RDN, and store it in vector
                RDN rdn = new RDN(rdnString, keywordMap);
                dnVector.add(rdn);

                // Increase the offset
                dnOffset = rdnEnd + 1;

                // Set quote counter back to zero
                quoteCount = 0;
            }

            searchOffset = rdnEnd + 1;
            nextComma = dname.indexOf(',', searchOffset);
            nextSemiColon = dname.indexOf(';', searchOffset);
        }

        // Parse last or only RDN, and store it in vector
        rdnString = dname.substring(dnOffset);
        RDN rdn = new RDN(rdnString, keywordMap);
        dnVector.add(rdn);

        /*
         * Store the vector elements as an array of RDNs
         * NOTE: It's only on output that little-endian ordering is used.
         */
        Collections.reverse(dnVector);
        names = dnVector.toArray(new RDN[0]);
    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private void parseRFC2253DN(String dnString) throws IOException {
        if (dnString.isEmpty()) {
            names = new RDN[0];
            return;
        }

        List<RDN> dnVector = new ArrayList<>();
        int dnOffset = 0;
        String rdnString;

        int searchOffset = 0;
        int rdnEnd = dnString.indexOf(',');
        while (rdnEnd >= 0) {
            /*
             * We have encountered an RDN delimiter (comma).
             * If the comma in the RDN under consideration is
             * preceded by a backslash (escape), it
             * is part of the RDN. Otherwise, it is used as a separator, to
             * delimit the RDN under consideration from any subsequent RDNs.
             */
            if (rdnEnd > 0 && !escaped(rdnEnd, searchOffset, dnString)) {

                /*
                 * Comma is a separator
                 */
                rdnString = dnString.substring(dnOffset, rdnEnd);

                // Parse RDN, and store it in vector
                RDN rdn = new RDN(rdnString, "RFC2253");
                dnVector.add(rdn);

                // Increase the offset
                dnOffset = rdnEnd + 1;
            }

            searchOffset = rdnEnd + 1;
            rdnEnd = dnString.indexOf(',', searchOffset);
        }

        // Parse last or only RDN, and store it in vector
        rdnString = dnString.substring(dnOffset);
        RDN rdn = new RDN(rdnString, "RFC2253");
        dnVector.add(rdn);

        /*
         * Store the vector elements as an array of RDNs
         * NOTE: It's only on output that little-endian ordering is used.
         */
        Collections.reverse(dnVector);
        names = dnVector.toArray(new RDN[0]);
    }

    /*
     * Counts double quotes in string.
     * Escaped quotes are ignored.
     */
    static int countQuotes(String string, int from, int to) {
        int count = 0;

        for (int i = from; i < to; i++) {
            if ((string.charAt(i) == '"' && i == from) ||
                    (string.charAt(i) == '"' && string.charAt(i - 1) != '\\')) {
                count++;
            }
        }

        return count;
    }

    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    private static boolean escaped(int rdnEnd, int searchOffset, String dnString) {

        if (rdnEnd == 1 && dnString.charAt(0) == '\\') {

            //  case 1:
            //  \,

            return true;

        } else if (rdnEnd > 1 && dnString.charAt(rdnEnd - 1) == '\\' &&
                dnString.charAt(rdnEnd - 2) != '\\') {

            //  case 2:
            //  foo\,

            return true;

        } else if (rdnEnd > 1 && dnString.charAt(rdnEnd - 1) == '\\' &&
                dnString.charAt(rdnEnd - 2) == '\\') {

            //  case 3:
            //  foo\\\\\,

            int count = 0;
            rdnEnd--;   // back up to last backSlash
            while (rdnEnd >= searchOffset) {
                if (dnString.charAt(rdnEnd) == '\\') {
                    count++;    // count consecutive backslashes
                }
                rdnEnd--;
            }

            // if count is odd, then rdnEnd is escaped
            return (count % 2) != 0;
        } else {
            return false;
        }
    }

    /*
     * Dump the printable form of a distinguished name.  Each relative
     * name is separated from the next by a ",", and assertions in the
     * relative names have "label=value" syntax.
     *
     * Uses RFC 1779 syntax (i.e. little-endian, comma separators)
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private void generateDN() {
        if (names.length == 1) {
            dn = names[0].toString();
            return;
        }

        StringBuilder sb = new StringBuilder(48);
        if (names != null) {
            for (int i = names.length - 1; i >= 0; i--) {
                if (i != names.length - 1) {
                    sb.append(", ");
                }
                sb.append(names[i].toString());
            }
        }
        dn = sb.toString();
    }

    /*
     * Maybe return a preallocated OID, to reduce storage costs
     * and speed recognition of common X.500 attributes.
     */
    static ObjectIdentifier intern(ObjectIdentifier oid) {
        ObjectIdentifier interned = internedOIDs.get(oid);
        if (interned != null) {
            return interned;
        }
        internedOIDs.put(oid, oid);
        return oid;
    }

    private static final Map<ObjectIdentifier, ObjectIdentifier> internedOIDs = new HashMap<>();

    /*
     * Selected OIDs from X.520
     * Includes all those specified in RFC 3280 as MUST or SHOULD
     * be recognized
     */
    private static final int[] commonName_data = {2, 5, 4, 3};
    private static final int[] SURNAME_DATA = {2, 5, 4, 4};
    private static final int[] SERIALNUMBER_DATA = {2, 5, 4, 5};
    private static final int[] countryName_data = {2, 5, 4, 6};
    private static final int[] localityName_data = {2, 5, 4, 7};
    private static final int[] stateName_data = {2, 5, 4, 8};
    private static final int[] streetAddress_data = {2, 5, 4, 9};
    private static final int[] orgName_data = {2, 5, 4, 10};
    private static final int[] orgUnitName_data = {2, 5, 4, 11};
    private static final int[] title_data = {2, 5, 4, 12};
    private static final int[] GIVENNAME_DATA = {2, 5, 4, 42};
    private static final int[] INITIALS_DATA = {2, 5, 4, 43};
    private static final int[] GENERATIONQUALIFIER_DATA = {2, 5, 4, 44};
    private static final int[] DNQUALIFIER_DATA = {2, 5, 4, 46};
    private static final int[] ipAddress_data = {1, 3, 6, 1, 4, 1, 42, 2, 11, 2, 1};
    private static final int[] DOMAIN_COMPONENT_DATA = {0, 9, 2342, 19200300, 100, 1, 25};
    private static final int[] userid_data = {0, 9, 2342, 19200300, 100, 1, 1};

    /**
     * OID for the "CN=" attribute, denoting a person's common name.
     */
    public static final ObjectIdentifier commonName_oid;
    /**
     * OID for the "C=" attribute, denoting a country.
     */
    public static final ObjectIdentifier countryName_oid;
    /**
     * OID for the "L=" attribute, denoting a locality (such as a city)
     */
    public static final ObjectIdentifier localityName_oid;
    /**
     * OID for the "O=" attribute, denoting an organization name
     */
    public static final ObjectIdentifier orgName_oid;
    /**
     * OID for the "OU=" attribute, denoting an organizational unit name
     */
    public static final ObjectIdentifier orgUnitName_oid;
    /**
     * OID for the "S=" attribute, denoting a state (such as Delaware)
     */
    public static final ObjectIdentifier stateName_oid;
    /**
     * OID for the "STREET=" attribute, denoting a street address.
     */
    public static final ObjectIdentifier streetAddress_oid;
    /**
     * OID for the "T=" attribute, denoting a person's title.
     */
    public static final ObjectIdentifier title_oid;
    /**
     * OID for the "DNQUALIFIER=" or "DNQ=" attribute, denoting DN
     * disambiguating information.
     */
    public static final ObjectIdentifier DNQUALIFIER_OID;
    /**
     * OID for the "SURNAME=" attribute, denoting a person's surname.
     */
    public static final ObjectIdentifier SURNAME_OID;
    /**
     * OID for the "GIVENNAME=" attribute, denoting a person's given name.
     */
    public static final ObjectIdentifier GIVENNAME_OID;
    /**
     * OID for the "INITIALS=" attribute, denoting a person's initials.
     */
    public static final ObjectIdentifier INITIALS_OID;
    /**
     * OID for the "GENERATION=" attribute, denoting Jr., II, etc.
     */
    public static final ObjectIdentifier GENERATIONQUALIFIER_OID;
    /**
     * OID for "IP=" IP address attributes, used with SKIP.
     */
    public static final ObjectIdentifier ipAddress_oid;
    /**
     * OID for "DC=" domain component attributes, used with DNS names in DN
     * format
     */
    public static final ObjectIdentifier DOMAIN_COMPONENT_OID;
    /**
     * OID for "UID=" denoting a user id, defined in RFCs 1274 & 2798.
     */
    public static final ObjectIdentifier userid_oid;
    /**
     * OID for the "SERIALNUMBER=" attribute, denoting a serial number for.
     * a name. Do not confuse with PKCS#9 issuerAndSerialNumber or the
     * certificate serial number.
     */
    public static final ObjectIdentifier SERIALNUMBER_OID;

    static {
        commonName_oid = intern(ObjectIdentifier.newInternal(commonName_data));
        SERIALNUMBER_OID = intern(ObjectIdentifier.newInternal(SERIALNUMBER_DATA));
        countryName_oid = intern(ObjectIdentifier.newInternal(countryName_data));
        localityName_oid = intern(ObjectIdentifier.newInternal(localityName_data));
        orgName_oid = intern(ObjectIdentifier.newInternal(orgName_data));
        orgUnitName_oid = intern(ObjectIdentifier.newInternal(orgUnitName_data));
        stateName_oid = intern(ObjectIdentifier.newInternal(stateName_data));
        streetAddress_oid = intern(ObjectIdentifier.newInternal(streetAddress_data));
        title_oid = intern(ObjectIdentifier.newInternal(title_data));
        DNQUALIFIER_OID = intern(ObjectIdentifier.newInternal(DNQUALIFIER_DATA));
        SURNAME_OID = intern(ObjectIdentifier.newInternal(SURNAME_DATA));
        GIVENNAME_OID = intern(ObjectIdentifier.newInternal(GIVENNAME_DATA));
        INITIALS_OID = intern(ObjectIdentifier.newInternal(INITIALS_DATA));
        GENERATIONQUALIFIER_OID = intern(ObjectIdentifier.newInternal(GENERATIONQUALIFIER_DATA));
        /*
         * OIDs from other sources which show up in X.500 names we
         * expect to deal with often
         */
        ipAddress_oid = intern(ObjectIdentifier.newInternal(ipAddress_data));
        /*
         * Domain component OID from RFC 1274, RFC 2247, RFC 3280
         */
        DOMAIN_COMPONENT_OID = intern(ObjectIdentifier.newInternal(DOMAIN_COMPONENT_DATA));
        userid_oid = intern(ObjectIdentifier.newInternal(userid_data));
    }

    /**
     * Return constraint type:<ul>
     * <li>NAME_DIFF_TYPE = -1: input name is different type from this name
     * (i.e. does not constrain)
     * <li>NAME_MATCH = 0: input name matches this name
     * <li>NAME_NARROWS = 1: input name narrows this name
     * <li>NAME_WIDENS = 2: input name widens this name
     * <li>NAME_SAME_TYPE = 3: input name does not match or narrow this name,
     * &       but is same type
     * </ul>.  These results are used in checking NameConstraints during
     * certification path verification.
     *
     * @param inputName to be checked for being constrained
     * @throws UnsupportedOperationException if name is not exact match, but
     *                                       narrowing and widening are not supported for this name type.
     * @return constraint type above
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public int constrains(GeneralNameInterface inputName)
            throws UnsupportedOperationException {
        int constraintType;
        if (inputName == null) {
            constraintType = NAME_DIFF_TYPE;
        } else if (inputName.getType() != NAME_DIRECTORY) {
            constraintType = NAME_DIFF_TYPE;
        } else { // type == NAME_DIRECTORY
            X500Name inputX500 = (X500Name) inputName;
            if (inputX500.equals(this)) {
                constraintType = NAME_MATCH;
            } else if (inputX500.names.length == 0) {
                constraintType = NAME_WIDENS;
            } else if (this.names.length == 0) {
                constraintType = NAME_NARROWS;
            } else if (inputX500.isWithinSubtree(this)) {
                constraintType = NAME_NARROWS;
            } else if (isWithinSubtree(inputX500)) {
                constraintType = NAME_WIDENS;
            } else {
                constraintType = NAME_SAME_TYPE;
            }
        }
        return constraintType;
    }

    /**
     * Compares this name with another and determines if
     * it is within the subtree of the other. Useful for
     * checking against the name constraints extension.
     *
     * @return true iff this name is within the subtree of other.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private boolean isWithinSubtree(X500Name other) {
        if (this == other) {
            return true;
        }
        if (other == null) {
            return false;
        }
        if (other.names.length == 0) {
            return true;
        }
        if (this.names.length == 0) {
            return false;
        }
        if (names.length < other.names.length) {
            return false;
        }
        for (int i = 0; i < other.names.length; i++) {
            if (!names[i].equals(other.names[i])) {
                return false;
            }
        }
        return true;
    }

    /**
     * Return subtree depth of this name for purposes of determining
     * NameConstraints minimum and maximum bounds and for calculating
     * path lengths in name subtrees.
     *
     * @throws UnsupportedOperationException if not supported for this name type
     * @return distance of name from root
     */
    public int subtreeDepth() throws UnsupportedOperationException {
        return names.length;
    }

    /**
     * Get an X500Principal backed by this X500Name.
     * <p>
     * Note that we are using privileged reflection to access the hidden
     * package private constructor in X500Principal.
     */
    @Nullable
    public X500Principal asX500Principal() {
        return x500Principal;
    }

}