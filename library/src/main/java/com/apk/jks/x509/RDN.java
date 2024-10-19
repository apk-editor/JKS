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
import androidx.annotation.RequiresApi;

import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

public class RDN {

    // currently not private, accessed directly from X500Name
    final AVA[] assertion;

    // cached immutable List of the AVAs
    private volatile List<AVA> avaList;

    // cache canonical String form
    private volatile String canonicalString;

    /*
     * Constructs an RDN from its printable representation.
     *
     * An RDN may consist of one or multiple Attribute Value Assertions (AVAs),
     * using '+' as a separator.
     * If the '+' should be considered part of an AVA value, it must be
     * preceded by '\'.
     *
     * @param name String form of RDN
     * @param keyword an additional mapping of keywords to OIDs
     * @throws IOException on parsing error
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public RDN(String name, Map<String, String> keywordMap) throws IOException {
        int quoteCount = 0;
        int searchOffset = 0;
        int avaOffset = 0;
        List<AVA> avaVec = new ArrayList<>(3);
        int nextPlus = name.indexOf('+');
        while (nextPlus >= 0) {
            quoteCount += X500Name.countQuotes(name, searchOffset, nextPlus);
            /*
             * We have encountered an AVA delimiter (plus sign).
             * If the plus sign in the RDN under consideration is
             * preceded by a backslash (escape), or by a double quote, it
             * is part of the AVA. Otherwise, it is used as a separator, to
             * delimit the AVA under consideration from any subsequent AVAs.
             */
            if (nextPlus > 0 && name.charAt(nextPlus - 1) != '\\'
                && quoteCount != 1) {
                /*
                 * Plus sign is a separator
                 */
                String avaString = name.substring(avaOffset, nextPlus);
                if (avaString.isEmpty()) {
                    throw new IOException("empty AVA in RDN \"" + name + "\"");
                }

                // Parse AVA, and store it in vector
                AVA ava = new AVA(new StringReader(avaString), keywordMap);
                avaVec.add(ava);

                // Increase the offset
                avaOffset = nextPlus + 1;

                // Set quote counter back to zero
                quoteCount = 0;
            }
            searchOffset = nextPlus + 1;
            nextPlus = name.indexOf('+', searchOffset);
        }

        // parse last or only AVA
        String avaString = name.substring(avaOffset);
        if (avaString.isEmpty()) {
            throw new IOException("empty AVA in RDN \"" + name + "\"");
        }
        AVA ava = new AVA(new StringReader(avaString), keywordMap);
        avaVec.add(ava);

        assertion = avaVec.toArray(new AVA[0]);
    }

    /*
     * Constructs an RDN from its printable representation.
     *
     * An RDN may consist of one or multiple Attribute Value Assertions (AVAs),
     * using '+' as a separator.
     * If the '+' should be considered part of an AVA value, it must be
     * preceded by '\'.
     *
     * @param name String form of RDN
     * @throws IOException on parsing error
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    RDN(String name, String format) throws IOException {
        this(name, format, Collections.emptyMap());
    }

    /*
     * Constructs an RDN from its printable representation.
     *
     * An RDN may consist of one or multiple Attribute Value Assertions (AVAs),
     * using '+' as a separator.
     * If the '+' should be considered part of an AVA value, it must be
     * preceded by '\'.
     *
     * @param name String form of RDN
     * @param keyword an additional mapping of keywords to OIDs
     * @throws IOException on parsing error
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    RDN(String name, String format, Map<String, String> keywordMap)
        throws IOException {
        if (!format.equalsIgnoreCase("RFC2253")) {
            throw new IOException("Unsupported format " + format);
        }
        int searchOffset;
        int avaOffset = 0;
        List<AVA> avaVec = new ArrayList<>(3);
        int nextPlus = name.indexOf('+');
        while (nextPlus >= 0) {
            /*
             * We have encountered an AVA delimiter (plus sign).
             * If the plus sign in the RDN under consideration is
             * preceded by a backslash (escape), or by a double quote, it
             * is part of the AVA. Otherwise, it is used as a separator, to
             * delimit the AVA under consideration from any subsequent AVAs.
             */
            if (nextPlus > 0 && name.charAt(nextPlus - 1) != '\\' ) {
                /*
                 * Plus sign is a separator
                 */
                String avaString = name.substring(avaOffset, nextPlus);
                if (avaString.isEmpty()) {
                    throw new IOException("empty AVA in RDN \"" + name + "\"");
                }

                // Parse AVA, and store it in vector
                AVA ava = new AVA
                    (new StringReader(avaString), AVA.RFC2253, keywordMap);
                avaVec.add(ava);

                // Increase the offset
                avaOffset = nextPlus + 1;
            }
            searchOffset = nextPlus + 1;
            nextPlus = name.indexOf('+', searchOffset);
        }

        // parse last or only AVA
        String avaString = name.substring(avaOffset);
        if (avaString.isEmpty()) {
            throw new IOException("empty AVA in RDN \"" + name + "\"");
        }
        AVA ava = new AVA(new StringReader(avaString), AVA.RFC2253, keywordMap);
        avaVec.add(ava);

        assertion = avaVec.toArray(new AVA[0]);
    }

    /*
     * Constructs an RDN from an ASN.1 encoded value.  The encoding
     * of the name in the stream uses DER (a BER/1 subset).
     *
     * @param value a DER-encoded value holding an RDN.
     * @throws IOException on parsing error.
     */
    RDN(DerValue rdn) throws IOException {
        if (rdn.tag != DerValue.tag_Set) {
            throw new IOException("X500 RDN");
        }
        DerInputStream dis = new DerInputStream(rdn.toByteArray());
        DerValue[] avaset = dis.getSet(5);

        assertion = new AVA[avaset.length];
        for (int i = 0; i < avaset.length; i++) {
            assertion[i] = new AVA(avaset[i]);
        }
    }

    /*
     * Creates an empty RDN with slots for specified
     * number of AVAs.
     *
     * @param i number of AVAs to be in RDN
     */
    RDN(int i) { assertion = new AVA[i]; }

    /**
     * Return the number of AVAs in this RDN.
     */
    public int size() {
        return assertion.length;
    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RDN)) {
            return false;
        }
        RDN other = (RDN)obj;
        if (this.assertion.length != other.assertion.length) {
            return false;
        }
        String thisCanon = this.toRFC2253String(true);
        String otherCanon = other.toRFC2253String(true);
        return thisCanon.equals(otherCanon);
    }

    /*
     * Calculates a hash code value for the object.  Objects
     * which are equal will also have the same hashcode.
     *
     * @returns int hashCode value
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public int hashCode() {
        return toRFC2253String(true).hashCode();
    }

    /*
     * Encode the RDN in DER-encoded form.
     *
     * @param out DerOutputStream to which RDN is to be written
     * @throws IOException on error
     */
    void encode(DerOutputStream out) throws IOException {
        out.putOrderedSetOf(DerValue.tag_Set, assertion);
    }

    /*
     * Returns a printable form of this RDN, using RFC 1779 style catenation
     * of attribute/value assertions, and emitting attribute type keywords
     * from RFCs 1779, 2253, and 3280.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    @NonNull
    public String toString() {
        if (assertion.length == 1) {
            return assertion[0].toString();
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < assertion.length; i++) {
            if (i != 0) {
                sb.append(" + ");
            }
            sb.append(assertion[i].toString());
        }
        return sb.toString();
    }

    /*
     * Returns a printable form of this RDN using the algorithm defined in
     * RFC 2253. RFC 2253 attribute type keywords are emitted, as well as
     * keywords contained in the OID/keyword map.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public String toRFC2253String(Map<String, String> oidMap) {
        return toRFC2253StringInternal(false, oidMap);
    }

    /*
     * Returns a printable form of this RDN using the algorithm defined in
     * RFC 2253. Only RFC 2253 attribute type keywords are emitted.
     * If canonical is true, then additional canonicalizations
     * documented in X500Principal.getName are performed.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public String toRFC2253String(boolean canonical) {
        if (!canonical) {
            return toRFC2253StringInternal
                (false, Collections.emptyMap());
        }
        String c = canonicalString;
        if (c == null) {
            c = toRFC2253StringInternal
                (true, Collections.emptyMap());
            canonicalString = c;
        }
        return c;
    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private String toRFC2253StringInternal
        (boolean canonical, Map<String, String> oidMap) {
        /*
         * Section 2.2: When converting from an ASN.1 RelativeDistinguishedName
         * to a string, the output consists of the string encodings of each
         * AttributeTypeAndValue (according to 2.3), in any order.
         *
         * Where there is a multi-valued RDN, the outputs from adjoining
         * AttributeTypeAndValues are separated by a plus ('+' ASCII 43)
         * character.
         */

        // normally, an RDN only contains one AVA
        if (assertion.length == 1) {
            return canonical ? assertion[0].toRFC2253CanonicalString() :
                               assertion[0].toRFC2253String(oidMap);
        }

        StringBuilder relname = new StringBuilder();
        if (!canonical) {
            for (int i = 0; i < assertion.length; i++) {
                if (i > 0) {
                    relname.append('+');
                }
                relname.append(assertion[i].toRFC2253String(oidMap));
            }
        } else {
            // order the string type AVA's alphabetically,
            // followed by the oid type AVA's numerically
            List<AVA> avaList = new ArrayList<>(assertion.length);
            Collections.addAll(avaList, assertion);
            java.util.Collections.sort(avaList, AVAComparator.getInstance());

            for (int i = 0; i < avaList.size(); i++) {
                if (i > 0) {
                    relname.append('+');
                }
                relname.append(avaList.get(i).toRFC2253CanonicalString());
            }
        }
        return relname.toString();
    }

}
class AVAComparator implements Comparator<AVA> {

    private static final Comparator<AVA> INSTANCE = new AVAComparator();

    private AVAComparator() {
        // empty
    }

    static Comparator<AVA> getInstance() {
        return INSTANCE;
    }

    /**
     * AVA's containing a standard keyword are ordered alphabetically,
     * followed by AVA's containing an OID keyword, ordered numerically
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public int compare(AVA a1, AVA a2) {
        boolean a1Has2253 = a1.hasRFC2253Keyword();
        boolean a2Has2253 = a2.hasRFC2253Keyword();

        if (a1Has2253 == a2Has2253) {
            return a1.toRFC2253CanonicalString().compareTo
                        (a2.toRFC2253CanonicalString());
        } else {
            if (a1Has2253) {
                return -1;
            } else {
                return 1;
            }
        }
    }

}