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

import androidx.annotation.NonNull;

import java.io.IOException;

import com.apk.jks.utils.BitArray;
import com.apk.jks.utils.DerOutputStream;
import com.apk.jks.utils.DerValue;

public class UniqueIdentity {

    private final BitArray id;

    /*
     * Create the object, decoding the values from the passed DER stream.
     *
     * @param derVal the DerValue decoded from the stream.
     * @param tag the tag the value is encoded under.
     * @exception IOException on decoding errors.
     */
    public UniqueIdentity(DerValue derVal) throws IOException {
        id = derVal.getUnalignedBitString(true);
    }

    /**
     * Return the UniqueIdentity as a printable string.
     */
    @NonNull
    public String toString() {
        return ("UniqueIdentity:" + id.toString() + "\n");
    }

    /**
     * Encode the UniqueIdentity in DER form to the stream.
     *
     * @param out the DerOutputStream to marshal the contents to.
     * @param tag enocode it under the following tag.
     * @exception IOException on errors.
     */
    public void encode(DerOutputStream out, byte tag) throws IOException {
        byte[] bytes = id.toByteArray();
        int excessBits = bytes.length*8 - id.length();

        out.write(tag);
        out.putLength(bytes.length + 1);

        out.write(excessBits);
        out.write(bytes);
    }

    /**
     * Return the unique id.
     */
    public boolean[] getId() {
        if (id == null) return null;

        return id.toBooleanArray();
    }

}