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

import com.apk.jks.utils.DerValue;

import androidx.annotation.NonNull;

import com.apk.jks.utils.DerInputStream;
import com.apk.jks.utils.DerOutputStream;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Hashtable;

public class CRLExtensions {

    private final Hashtable<String, Extension> map = new Hashtable<>();
    private boolean unsupportedCritExt = false;

    /**
     * Create the object, decoding the values from the passed DER stream.
     *
     * @param in the DerInputStream to read the Extension from, i.e. the
     *        sequence of extensions.
     * @exception CRLException on decoding errors.
     */
    public CRLExtensions(DerInputStream in) throws CRLException {
        init(in);
    }

    // helper routine
    private void init(DerInputStream derStrm) throws CRLException {
        try {
            DerInputStream str = derStrm;

            byte nextByte = (byte)derStrm.peekByte();
            // check for context specific byte 0; skip it
            if (((nextByte & 0x0c0) == 0x080) &&
                ((nextByte & 0x01f) == 0x000)) {
                DerValue val = str.getDerValue();
                str = val.data;
            }

            DerValue[] exts = str.getSequence(5);
            for (DerValue derValue : exts) {
                Extension ext = new Extension(derValue);
                parseExtension(ext);
            }
        } catch (IOException e) {
            throw new CRLException("Parsing error: " + e);
        }
    }

    private static final Class[] PARAMS = {Boolean.class, Object.class};

    // Parse the encoded extension
    private void parseExtension(Extension ext) throws CRLException {
        try {
            Class extClass = OIDMap.getClass(ext.getExtensionId());
            if (extClass == null) {   // Unsupported extension
                if (ext.isCritical())
                    unsupportedCritExt = true;
                if (map.put(ext.getExtensionId().toString(), ext) != null)
                    throw new CRLException("Duplicate extensions not allowed");
                return;
            }
            Constructor<?> cons = ((Class<?>)extClass).getConstructor(PARAMS);
            Object[] passed = new Object[] {ext.isCritical(),
                                            ext.getExtensionValue()};
            CertAttrSet crlExt = (CertAttrSet)cons.newInstance(passed);
            if (map.put(crlExt.getName(), (Extension)crlExt) != null) {
                throw new CRLException("Duplicate extensions not allowed");
            }
        } catch (InvocationTargetException invk) {
            throw new CRLException(invk.getTargetException().getMessage());
        } catch (Exception e) {
            throw new CRLException(e.toString());
        }
    }

    /**
     * Encode the extensions in DER form to the stream.
     *
     * @param out the DerOutputStream to marshal the contents to.
     * @param isExplicit the tag indicating whether this is an entry
     * extension (false) or a CRL extension (true).
     * @exception CRLException on encoding errors.
     */
    public void encode(OutputStream out, boolean isExplicit)
    throws CRLException {
        try {
            DerOutputStream extOut = new DerOutputStream();
            Collection<Extension> allExts = map.values();
            Object[] objs = allExts.toArray();

            for (Object obj : objs) {
                if (obj instanceof CertAttrSet)
                    ((CertAttrSet) obj).encode(extOut);
                else if (obj instanceof Extension)
                    ((Extension) obj).encode(extOut);
                else
                    throw new CRLException("Illegal extension object");
            }

            DerOutputStream seq = new DerOutputStream();
            seq.write(DerValue.tag_Sequence, extOut);

            DerOutputStream tmp = new DerOutputStream();
            if (isExplicit)
                tmp.write(DerValue.createTag(DerValue.TAG_CONTEXT,
                                             true, (byte)0), seq);
            else
                tmp = seq;

            out.write(tmp.toByteArray());
        } catch (IOException | CertificateException e) {
            throw new CRLException("Encoding error: " + e);
        }
    }

    /**
     * Get the extension with this alias.
     *
     * @param alias the identifier string for the extension to retrieve.
     */
    public Extension get(String alias) {
        X509AttributeName attr = new X509AttributeName(alias);
        String name;
        String id = attr.getPrefix();
        if (id.equalsIgnoreCase(X509CertImpl.NAME)) { // fully qualified
            int index = alias.lastIndexOf(".");
            name = alias.substring(index + 1);
        } else
            name = alias;
        return map.get(name);
    }

    /**
     * Set the extension value with this alias.
     *
     * @param alias the identifier string for the extension to set.
     * @param obj the Object to set the extension identified by the
     *        alias.
     */
    public void set(String alias, Object obj) {
        map.put(alias, (Extension)obj);
    }

    /**
     * Delete the extension value with this alias.
     *
     * @param alias the identifier string for the extension to delete.
     */
    public void delete(String alias) {
        map.remove(alias);
    }

    /**
     * Return an enumeration of the extensions.
     * @return an enumeration of the extensions in this CRL.
     */
    public Enumeration<Extension> getElements() {
        return map.elements();
    }

    /**
     * Return a collection view of the extensions.
     * @return a collection view of the extensions in this CRL.
     */
    public Collection<Extension> getAllExtensions() {
        return map.values();
    }

    /**
     * Return true if a critical extension is found that is
     * not supported, otherwise return false.
     */
    public boolean hasUnsupportedCriticalExtension() {
        return unsupportedCritExt;
    }

    /**
     * Compares this CRLExtensions for equality with the specified
     * object. If the <code>other</code> object is an
     * <code>instanceof</code> <code>CRLExtensions</code>, then
     * all the entries are compared with the entries from this.
     *
     * @param other the object to test for equality with this CRLExtensions.
     * @return true iff all the entries match that of the Other,
     * false otherwise.
     */
    public boolean equals(Object other) {
        if (this == other)
            return true;
        if (!(other instanceof CRLExtensions))
            return false;
        Collection<Extension> otherC =
                        ((CRLExtensions)other).getAllExtensions();
        Object[] objs = otherC.toArray();

        int len = objs.length;
        if (len != map.size())
            return false;

        Extension otherExt, thisExt;
        String key = null;
        for (Object obj : objs) {
            if (obj instanceof CertAttrSet)
                key = ((CertAttrSet<?>) obj).getName();
            otherExt = (Extension) obj;
            if (key == null)
                key = otherExt.getExtensionId().toString();
            thisExt = map.get(key);
            if (thisExt == null)
                return false;
            if (!thisExt.equals(otherExt))
                return false;
        }
        return true;
    }

    /**
     * Returns a hashcode value for this CRLExtensions.
     *
     * @return the hashcode value.
     */
    public int hashCode() {
        return map.hashCode();
    }

    /**
     * Returns a string representation of this <tt>CRLExtensions</tt> object
     * in the form of a set of entries, enclosed in braces and separated
     * by the ASCII characters "<tt>,&nbsp;</tt>" (comma and space).
     * <p>Overrides to <tt>toString</tt> method of <tt>Object</tt>.
     *
     * @return  a string representation of this CRLExtensions.
     */
    @NonNull
    public String toString() {
        return map.toString();
    }
}