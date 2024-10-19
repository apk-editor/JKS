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

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import java.io.IOException;
import java.util.Enumeration;

import com.apk.jks.utils.BitArray;
import com.apk.jks.utils.DerOutputStream;

public class ReasonFlags {

    /**
     * Reasons
     */
    public static final String UNUSED = "unused";
    public static final String KEY_COMPROMISE = "key_compromise";
    public static final String CA_COMPROMISE = "ca_compromise";
    public static final String AFFILIATION_CHANGED = "affiliation_changed";
    public static final String SUPERSEDED = "superseded";
    public static final String CESSATION_OF_OPERATION
                                   = "cessation_of_operation";
    public static final String CERTIFICATE_HOLD = "certificate_hold";
    public static final String PRIVILEGE_WITHDRAWN = "privilege_withdrawn";
    public static final String AA_COMPROMISE = "aa_compromise";

    private final static String[] NAMES = {
        UNUSED,
        KEY_COMPROMISE,
        CA_COMPROMISE,
        AFFILIATION_CHANGED,
        SUPERSEDED,
        CESSATION_OF_OPERATION,
        CERTIFICATE_HOLD,
        PRIVILEGE_WITHDRAWN,
        AA_COMPROMISE,
    };

    private static int name2Index(String name) throws IOException {
        for( int i=0; i<NAMES.length; i++ ) {
            if( NAMES[i].equalsIgnoreCase(name) ) {
                return i;
            }
        }
        throw new IOException("Name not recognized by ReasonFlags");
    }

    // Private data members
    private boolean[] bitString;

    /**
     * Check if bit is set.
     *
     * @param position the position in the bit string to check.
     */
    private boolean isSet(int position) {
        return bitString[position];
    }

    /**
     * Set the bit at the specified position.
     */
    private void set(int position, boolean val) {
        // enlarge bitString if necessary
        if (position >= bitString.length) {
            boolean[] tmp = new boolean[position+1];
            System.arraycopy(bitString, 0, tmp, 0, bitString.length);
            bitString = tmp;
        }
        bitString[position] = val;
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        if (!(obj instanceof Boolean)) {
            throw new IOException("Attribute must be of type Boolean.");
        }
        boolean val = (Boolean) obj;
        set(name2Index(name), val);
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        return isSet(name2Index(name));
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        set(name, Boolean.FALSE);
    }

    /**
     * Returns a printable representation of the ReasonFlags.
     */
    @NonNull
    public String toString() {
        String s = "Reason Flags [\n";

        try {
            if (isSet(0)) s += "  Unused\n";
            if (isSet(1)) s += "  Key Compromise\n";
            if (isSet(2)) s += "  CA Compromise\n";
            if (isSet(3)) s += "  Affiliation_Changed\n";
            if (isSet(4)) s += "  Superseded\n";
            if (isSet(5)) s += "  Cessation Of Operation\n";
            if (isSet(6)) s += "  Certificate Hold\n";
            if (isSet(7)) s += "  Privilege Withdrawn\n";
            if (isSet(8)) s += "  AA Compromise\n";
        } catch (ArrayIndexOutOfBoundsException ignored) {}

        s += "]\n";

        return (s);
    }

    /**
     * Write the extension to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the extension to.
     * @exception IOException on encoding errors.
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    public void encode(DerOutputStream out) throws IOException {
        out.putTruncatedUnalignedBitString(new BitArray(this.bitString));
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getElements () {
        AttributeNameEnumeration elements = new AttributeNameEnumeration();
        for (String name : NAMES) {
            elements.addElement(name);
        }
        return (elements.elements());
    }
}