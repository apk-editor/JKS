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

import com.apk.jks.utils.DerOutputStream;

import java.io.IOException;

public class CertificatePolicyMap {
    private final CertificatePolicyId issuerDomain;
    private final CertificatePolicyId subjectDomain;

    /**
     * Create the CertificatePolicyMap from the DER encoded value.
     *
     * @param val the DER encoded value of the same.
     */
    public CertificatePolicyMap(DerValue val) throws IOException {
        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding for CertificatePolicyMap");
        }
        issuerDomain = new CertificatePolicyId(val.data.getDerValue());
        subjectDomain = new CertificatePolicyId(val.data.getDerValue());
    }

    /**
     * Returns a printable representation of the CertificatePolicyId.
     */
    @NonNull
    public String toString() {

        return ("CertificatePolicyMap: [\n"
                 + "IssuerDomain:" + issuerDomain.toString()
                 + "SubjectDomain:" + subjectDomain.toString()
                 + "]\n");
    }

    /**
     * Write the CertificatePolicyMap to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the object to.
     * @exception IOException on errors.
     */
    public void encode(DerOutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();

        issuerDomain.encode(tmp);
        subjectDomain.encode(tmp);
        out.write(DerValue.tag_Sequence,tmp);
    }
}