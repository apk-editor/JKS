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

import com.apk.jks.utils.BitArray;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Vector;

import com.apk.jks.utils.DerOutputStream;
import com.apk.jks.utils.ObjectIdentifier;

public class NetscapeCertTypeExtension extends Extension implements CertAttrSet<String> {

    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.extensions.NetscapeCertType";

    /**
     * Attribute names.
     */
    public static final String NAME = "NetscapeCertType";
    public static final String SSL_CLIENT = "ssl_client";
    public static final String SSL_SERVER = "ssl_server";
    public static final String S_MIME = "s_mime";
    public static final String OBJECT_SIGNING = "object_signing";
    public static final String SSL_CA = "ssl_ca";
    public static final String S_MIME_CA = "s_mime_ca";
    public static final String OBJECT_SIGNING_CA = "object_signing_ca";

    private static final int[] CertType_data = { 2, 16, 840, 1, 113730, 1, 1 };

    /**
     * Object identifier for the Netscape-Cert-Type extension.
     */
    public static ObjectIdentifier NetscapeCertType_Id;

    static {
        try {
            NetscapeCertType_Id = new ObjectIdentifier(CertType_data);
        } catch (IOException ioe) {
            // should not happen
        }
    }

    private boolean[] bitString;

    private static class MapEntry {
        String mName;
        int mPosition;

        MapEntry(String name, int position) {
            mName = name;
            mPosition = position;
        }
    }

    private static final MapEntry[] mMapData = {
        new MapEntry(SSL_CLIENT, 0),
        new MapEntry(SSL_SERVER, 1),
        new MapEntry(S_MIME, 2),
        new MapEntry(OBJECT_SIGNING, 3),
        // note that bit 4 is reserved
        new MapEntry(SSL_CA, 5),
        new MapEntry(S_MIME_CA, 6),
        new MapEntry(OBJECT_SIGNING_CA, 7),
    };

    private static final Vector<String> mAttributeNames = new Vector<>();
    static {
        for (MapEntry entry : mMapData) {
            mAttributeNames.add(entry.mName);
        }
    }

    private static int getPosition(String name) throws IOException {
        for (MapEntry mMapDatum : mMapData) {
            if (name.equalsIgnoreCase(mMapDatum.mName))
                return mMapDatum.mPosition;
        }
        throw new IOException("Attribute name [" + name
                             + "] not recognized by CertAttrSet:NetscapeCertType.");
    }

    // Encode this extension value
    private void encodeThis() throws IOException {
        DerOutputStream os = new DerOutputStream();
        os.putTruncatedUnalignedBitString(new BitArray(this.bitString));
        this.extensionValue = os.toByteArray();
    }

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
        if (!(obj instanceof Boolean))
            throw new IOException("Attribute must be of type Boolean.");

        boolean val = (Boolean) obj;
        set(getPosition(name), val);
        encodeThis();
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        return isSet(getPosition(name));
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        set(getPosition(name), false);
        encodeThis();
    }

    /**
     * Returns a printable representation of the NetscapeCertType.
     */
    @NonNull
    public String toString() {
        String s = super.toString() + "NetscapeCertType [\n";

        try {
           if (isSet(getPosition(SSL_CLIENT)))
               s += "   SSL client\n";
           if (isSet(getPosition(SSL_SERVER)))
               s += "   SSL server\n";
           if (isSet(getPosition(S_MIME)))
               s += "   S/MIME\n";
           if (isSet(getPosition(OBJECT_SIGNING)))
               s += "   Object Signing\n";
           if (isSet(getPosition(SSL_CA)))
               s += "   SSL CA\n";
           if (isSet(getPosition(S_MIME_CA)))
               s += "   S/MIME CA\n";
           if (isSet(getPosition(OBJECT_SIGNING_CA)))
               s += "   Object Signing CA" ;
        } catch (Exception ignored) { }

        s += "]\n";
        return (s);
    }

    /**
     * Write the extension to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the extension to.
     * @exception IOException on encoding errors.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();

        if (this.extensionValue == null) {
            this.extensionId = NetscapeCertType_Id;
            this.critical = true;
            encodeThis();
        }
        super.encode(tmp);
        out.write(tmp.toByteArray());
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getElements() {
        return mAttributeNames.elements();
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }
}