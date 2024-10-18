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

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import com.apk.jks.utils.DerValue;
import com.apk.jks.utils.DerOutputStream;
import com.apk.jks.utils.ObjectIdentifier;

import androidx.annotation.NonNull;

public class ExtendedKeyUsageExtension extends Extension
implements CertAttrSet<String> {

    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.extensions.ExtendedKeyUsage";

    /**
     * Attribute names.
     */
    public static final String NAME = "ExtendedKeyUsage";
    public static final String USAGES = "usages";

    // OID defined in RFC 3280 Sections 4.2.1.13
    // more from http://www.alvestrand.no/objectid/1.3.6.1.5.5.7.3.html
    private static final Map <ObjectIdentifier, String> map =
            new HashMap<>();

    private static final int[] anyExtendedKeyUsageOidData = {2, 5, 29, 37, 0};
    private static final int[] serverAuthOidData = {1, 3, 6, 1, 5, 5, 7, 3, 1};
    private static final int[] clientAuthOidData = {1, 3, 6, 1, 5, 5, 7, 3, 2};
    private static final int[] codeSigningOidData = {1, 3, 6, 1, 5, 5, 7, 3, 3};
    private static final int[] emailProtectionOidData = {1, 3, 6, 1, 5, 5, 7, 3, 4};
    private static final int[] ipsecEndSystemOidData = {1, 3, 6, 1, 5, 5, 7, 3, 5};
    private static final int[] ipsecTunnelOidData = {1, 3, 6, 1, 5, 5, 7, 3, 6};
    private static final int[] ipsecUserOidData = {1, 3, 6, 1, 5, 5, 7, 3, 7};
    private static final int[] timeStampingOidData = {1, 3, 6, 1, 5, 5, 7, 3, 8};
    private static final int[] OCSPSigningOidData = {1, 3, 6, 1, 5, 5, 7, 3, 9};

    static {
        map.put(ObjectIdentifier.newInternal(anyExtendedKeyUsageOidData), "anyExtendedKeyUsage");
        map.put(ObjectIdentifier.newInternal(serverAuthOidData), "serverAuth");
        map.put(ObjectIdentifier.newInternal(clientAuthOidData), "clientAuth");
        map.put(ObjectIdentifier.newInternal(codeSigningOidData), "codeSigning");
        map.put(ObjectIdentifier.newInternal(emailProtectionOidData), "emailProtection");
        map.put(ObjectIdentifier.newInternal(ipsecEndSystemOidData), "ipsecEndSystem");
        map.put(ObjectIdentifier.newInternal(ipsecTunnelOidData), "ipsecTunnel");
        map.put(ObjectIdentifier.newInternal(ipsecUserOidData), "ipsecUser");
        map.put(ObjectIdentifier.newInternal(timeStampingOidData), "timeStamping");
        map.put(ObjectIdentifier.newInternal(OCSPSigningOidData), "OCSPSigning");
    }

    /**
     * Vector of KeyUsages for this object.
     */
    private Vector<ObjectIdentifier> keyUsages;

    // Encode this extension value.
    private void encodeThis() throws IOException {
        if (keyUsages == null || keyUsages.isEmpty()) {
            this.extensionValue = null;
            return;
        }
        DerOutputStream os = new DerOutputStream();
        DerOutputStream tmp = new DerOutputStream();

        for (int i = 0; i < keyUsages.size(); i++) {
            tmp.putOID(keyUsages.elementAt(i));
        }

        os.write(DerValue.tag_Sequence, tmp);
        this.extensionValue = os.toByteArray();
    }

    /**
     * Create the extension from its DER encoded value and criticality.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param value an array of DER encoded bytes of the actual value.
     * @exception ClassCastException if value is not an array of bytes
     * @exception IOException on error.
     */
    public ExtendedKeyUsageExtension(Boolean critical, Object value)
    throws IOException {
        this.extensionId = PKIXExtensions.ExtendedKeyUsage_Id;
        this.critical = critical;
        this.extensionValue = (byte[]) value;
        DerValue val = new DerValue(this.extensionValue);
        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding for " +
                                   "ExtendedKeyUsageExtension.");
        }
        keyUsages = new Vector<>();
        while (val.data.available() != 0) {
            DerValue seq = val.data.getDerValue();
            ObjectIdentifier usage = seq.getOID();
            keyUsages.addElement(usage);
        }
    }

    /**
     * Return the extension as user readable string.
     */
    @NonNull
    public String toString() {
        if (keyUsages == null) return "";
        StringBuilder usage = new StringBuilder("  ");
        boolean first = true;
        for (ObjectIdentifier oid: keyUsages) {
            if(!first) {
                usage.append("\n  ");
            }

            String result = map.get(oid);
            if (result != null) {
                usage.append(result);
            } else {
                usage.append(oid.toString());
            }
            first = false;
        }
        return super.toString() + "ExtendedKeyUsages [\n"
               + usage + "\n]\n";
    }

    /**
     * Write the extension to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the extension to.
     * @exception IOException on encoding errors.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        if (extensionValue == null) {
          extensionId = PKIXExtensions.ExtendedKeyUsage_Id;
          critical = false;
          encodeThis();
        }
        super.encode(tmp);
        out.write(tmp.toByteArray());
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        if (name.equalsIgnoreCase(USAGES)) {
            if (!(obj instanceof Vector)) {
                throw new IOException("Attribute value should be of type Vector.");
            }
            this.keyUsages = (Vector<ObjectIdentifier>)obj;
        } else {
          throw new IOException("Attribute name [" + name +
                                "] not recognized by " +
                                "CertAttrSet:ExtendedKeyUsageExtension.");
        }
        encodeThis();
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(USAGES)) {
            //XXXX May want to consider cloning this
            return keyUsages;
        } else {
          throw new IOException("Attribute name [" + name +
                                "] not recognized by " +
                                "CertAttrSet:ExtendedKeyUsageExtension.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(USAGES)) {
            keyUsages = null;
        } else {
          throw new IOException("Attribute name [" + name +
                                "] not recognized by " +
                                "CertAttrSet:ExtendedKeyUsageExtension.");
        }
        encodeThis();
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getElements() {
        AttributeNameEnumeration elements = new AttributeNameEnumeration();
        elements.addElement(USAGES);

        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }

    public List<String> getExtendedKeyUsage() {
        List<String> al = new ArrayList<>(keyUsages.size());
        for (ObjectIdentifier oid : keyUsages) {
            al.add(oid.toString());
        }
        return al;
    }

}