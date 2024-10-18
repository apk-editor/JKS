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

import com.apk.jks.utils.HexDumpEncoder;
import com.apk.jks.utils.DerValue;
import com.apk.jks.x509.GeneralNames;
import com.apk.jks.x509.SerialNumber;

import androidx.annotation.NonNull;

import java.io.IOException;

public class SigningCertificateInfo {

    private ESSCertId[] certId = null;

    public SigningCertificateInfo(byte[] ber) throws IOException {
        parse(ber);
    }

    @NonNull
    public String toString() {
        StringBuilder buffer = new StringBuilder();
        buffer.append("[\n");
        for (ESSCertId essCertId : certId) {
            buffer.append(essCertId.toString());
        }
        // format policies as a string
        buffer.append("\n]");

        return buffer.toString();
    }

    public void parse(byte[] bytes) throws IOException {

        // Parse signingCertificate
        DerValue derValue = new DerValue(bytes);
        if (derValue.tag != DerValue.tag_Sequence) {
            throw new IOException("Bad encoding for signingCertificate");
        }

        // Parse certs
        DerValue[] certs = derValue.data.getSequence(1);
        certId = new ESSCertId[certs.length];
        for (int i = 0; i < certs.length; i++) {
            certId[i] = new ESSCertId(certs[i]);
        }
    }
}

class ESSCertId {

    private static volatile HexDumpEncoder hexDumper;

    private final byte[] certHash;
    private GeneralNames issuer;
    private SerialNumber serialNumber;

    ESSCertId(DerValue certId) throws IOException {
        // Parse certHash
        certHash = certId.data.getDerValue().toByteArray();

        // Parse issuerSerial, if present
        if (certId.data.available() > 0) {
            DerValue issuerSerial = certId.data.getDerValue();
            // Parse issuer
            issuer = new GeneralNames(issuerSerial.data.getDerValue());
            // Parse serialNumber
            serialNumber = new SerialNumber(issuerSerial.data.getDerValue());
        }
    }

    @NonNull
    public String toString() {
        StringBuilder buffer = new StringBuilder();
        buffer.append("[\n\tCertificate hash (SHA-1):\n");
        if (hexDumper == null) {
            hexDumper = new HexDumpEncoder();
        }
        buffer.append(hexDumper.encode(certHash));
        if (issuer != null && serialNumber != null) {
            buffer.append("\n\tIssuer: ").append(issuer).append("\n");
            buffer.append("\t").append(serialNumber);
        }
        buffer.append("\n]");
        return buffer.toString();
    }
}