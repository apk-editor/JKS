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

package com.apk.jks.ec;

import com.apk.jks.x509.AlgorithmId;
import com.apk.jks.x509.X509Key;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyRep;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidParameterSpecException;

public final class ECPublicKeyImpl extends X509Key implements ECPublicKey {

    private static final long serialVersionUID = -2462037275160462289L;

    private ECPoint w;
    private ECParameterSpec params;

    /**
     * Construct a key from its components. Used by the
     * ECKeyFactory and SunPKCS11.
     */
    public ECPublicKeyImpl(ECPoint w, ECParameterSpec params)
            throws InvalidKeyException {
        this.w = w;
        this.params = params;
        // generate the encoding
        algid = new AlgorithmId
            (AlgorithmId.EC_oid, ECParameters.getAlgorithmParameters(params));
        key = ECParameters.encodePoint(w, params.getCurve());
    }

    /**
     * Construct a key from its encoding. Used by RSAKeyFactory.
     */
    public ECPublicKeyImpl(byte[] encoded) throws InvalidKeyException {
        decode(encoded);
    }

    // see JCA doc
    public String getAlgorithm() {
        return "EC";
    }

    // see JCA doc
    public ECPoint getW() {
        return w;
    }

    // see JCA doc
    public ECParameterSpec getParams() {
        return params;
    }

    /**
     * Parse the key. Called by X509Key.
     */
    protected void parseKeyBits() throws InvalidKeyException {
        try {
            AlgorithmParameters algParams = this.algid.getParameters();
            params = algParams.getParameterSpec(ECParameterSpec.class);
            w = ECParameters.decodePoint(key, params.getCurve());
        } catch (IOException | InvalidParameterSpecException e) {
            throw new InvalidKeyException("Invalid EC key", e);
        }
    }

    // return a string representation of this key for debugging
    @NonNull
    public String toString() {
        return "Sun EC public key, " + params.getCurve().getField().getFieldSize()
            + " bits\n  public x coord: " + w.getAffineX()
            + "\n  public y coord: " + w.getAffineY()
            + "\n  parameters: " + params;
    }

    private Object writeReplace() throws java.io.ObjectStreamException {
        return new KeyRep(KeyRep.Type.PUBLIC,
                        getAlgorithm(),
                        getFormat(),
                        getEncoded());
    }
}