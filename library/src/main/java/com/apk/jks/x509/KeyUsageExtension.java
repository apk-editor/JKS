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

import com.apk.jks.utils.BitArray;
import com.apk.jks.utils.DerOutputStream;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Enumeration;

public class KeyUsageExtension extends Extension implements CertAttrSet<String> {

    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.extensions.KeyUsage";
    /**
     * Attribute names.
     */
    public static final String NAME = "KeyUsage";
    public static final String DIGITAL_SIGNATURE = "digital_signature";
    public static final String NON_REPUDIATION = "non_repudiation";
    public static final String KEY_ENCIPHERMENT = "key_encipherment";
    public static final String DATA_ENCIPHERMENT = "data_encipherment";
    public static final String KEY_AGREEMENT = "key_agreement";
    public static final String KEY_CERTSIGN = "key_certsign";
    public static final String CRL_SIGN = "crl_sign";
    public static final String ENCIPHER_ONLY = "encipher_only";
    public static final String DECIPHER_ONLY = "decipher_only";

    // Private data members
    private boolean[] bitString;

    // Encode this extension value
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
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
     * Create a KeyUsageExtension with the passed bit settings. The criticality
     * is set to true.
     *
     * @param bitString the bits to be set for the extension.
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    public KeyUsageExtension(boolean[] bitString) throws IOException {
        this.bitString = bitString;
        this.extensionId = PKIXExtensions.KeyUsage_Id;
        this.critical = true;
        encodeThis();
    }

    /**
     * Set the attribute value.
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    public void set(String name, Object obj) throws IOException {
        if (!(obj instanceof Boolean)) {
            throw new IOException("Attribute must be of type Boolean.");
        }
        boolean val = (Boolean) obj;
        if (name.equalsIgnoreCase(DIGITAL_SIGNATURE)) {
            set(0,val);
        } else if (name.equalsIgnoreCase(NON_REPUDIATION)) {
            set(1,val);
        } else if (name.equalsIgnoreCase(KEY_ENCIPHERMENT)) {
            set(2,val);
        } else if (name.equalsIgnoreCase(DATA_ENCIPHERMENT)) {
            set(3,val);
        } else if (name.equalsIgnoreCase(KEY_AGREEMENT)) {
            set(4,val);
        } else if (name.equalsIgnoreCase(KEY_CERTSIGN)) {
            set(5,val);
        } else if (name.equalsIgnoreCase(CRL_SIGN)) {
            set(6,val);
        } else if (name.equalsIgnoreCase(ENCIPHER_ONLY)) {
            set(7,val);
        } else if (name.equalsIgnoreCase(DECIPHER_ONLY)) {
            set(8,val);
        } else {
          throw new IOException("Attribute name not recognized by"
                                + " CertAttrSet:KeyUsage.");
        }
        encodeThis();
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(DIGITAL_SIGNATURE)) {
            return isSet(0);
        } else if (name.equalsIgnoreCase(NON_REPUDIATION)) {
            return isSet(1);
        } else if (name.equalsIgnoreCase(KEY_ENCIPHERMENT)) {
            return isSet(2);
        } else if (name.equalsIgnoreCase(DATA_ENCIPHERMENT)) {
            return isSet(3);
        } else if (name.equalsIgnoreCase(KEY_AGREEMENT)) {
            return isSet(4);
        } else if (name.equalsIgnoreCase(KEY_CERTSIGN)) {
            return isSet(5);
        } else if (name.equalsIgnoreCase(CRL_SIGN)) {
            return isSet(6);
        } else if (name.equalsIgnoreCase(ENCIPHER_ONLY)) {
            return isSet(7);
        } else if (name.equalsIgnoreCase(DECIPHER_ONLY)) {
            return isSet(8);
        } else {
          throw new IOException("Attribute name not recognized by"
                                + " CertAttrSet:KeyUsage.");
        }
    }

    /**
     * Delete the attribute value.
     */
    @RequiresApi(api = Build.VERSION_CODES.GINGERBREAD)
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(DIGITAL_SIGNATURE)) {
            set(0,false);
        } else if (name.equalsIgnoreCase(NON_REPUDIATION)) {
            set(1,false);
        } else if (name.equalsIgnoreCase(KEY_ENCIPHERMENT)) {
            set(2,false);
        } else if (name.equalsIgnoreCase(DATA_ENCIPHERMENT)) {
            set(3,false);
        } else if (name.equalsIgnoreCase(KEY_AGREEMENT)) {
            set(4,false);
        } else if (name.equalsIgnoreCase(KEY_CERTSIGN)) {
            set(5,false);
        } else if (name.equalsIgnoreCase(CRL_SIGN)) {
            set(6,false);
        } else if (name.equalsIgnoreCase(ENCIPHER_ONLY)) {
            set(7,false);
        } else if (name.equalsIgnoreCase(DECIPHER_ONLY)) {
            set(8,false);
        } else {
          throw new IOException("Attribute name not recognized by"
                                + " CertAttrSet:KeyUsage.");
        }
        encodeThis();
    }

    /**
     * Returns a printable representation of the KeyUsage.
     */
    @NonNull
    public String toString() {
        String s = super.toString() + "KeyUsage [\n";

        try {
            if (isSet(0)) {
                s += "  DigitalSignature\n";
            }
            if (isSet(1)) {
                s += "  Non_repudiation\n";
            }
            if (isSet(2)) {
                s += "  Key_Encipherment\n";
            }
            if (isSet(3)) {
                s += "  Data_Encipherment\n";
            }
            if (isSet(4)) {
                s += "  Key_Agreement\n";
            }
            if (isSet(5)) {
                s += "  Key_CertSign\n";
            }
            if (isSet(6)) {
                s += "  Crl_Sign\n";
            }
            if (isSet(7)) {
                s += "  Encipher_Only\n";
            }
            if (isSet(8)) {
                s += "  Decipher_Only\n";
            }
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
    public void encode(OutputStream out) throws IOException {
       DerOutputStream tmp = new DerOutputStream();

       if (this.extensionValue == null) {
           this.extensionId = PKIXExtensions.KeyUsage_Id;
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
        AttributeNameEnumeration elements = new AttributeNameEnumeration();
        elements.addElement(DIGITAL_SIGNATURE);
        elements.addElement(NON_REPUDIATION);
        elements.addElement(KEY_ENCIPHERMENT);
        elements.addElement(DATA_ENCIPHERMENT);
        elements.addElement(KEY_AGREEMENT);
        elements.addElement(KEY_CERTSIGN);
        elements.addElement(CRL_SIGN);
        elements.addElement(ENCIPHER_ONLY);
        elements.addElement(DECIPHER_ONLY);

        return (elements.elements());
    }


    public boolean[] getBits() {
        return bitString.clone();
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }
}