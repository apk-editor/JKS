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

import com.apk.jks.utils.DerOutputStream;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import com.apk.jks.utils.DerInputStream;
import com.apk.jks.utils.DerValue;

import java.io.IOException;

public class EDIPartyName implements GeneralNameInterface {

    // Private data members
    private static final byte TAG_ASSIGNER = 0;
    private static final byte TAG_PARTYNAME = 1;

    private String assigner = null;
    private String party = null;

    private int myhash = -1;

    /**
     * Create the EDIPartyName object from the passed encoded Der value.
     *
     * @param derValue the encoded DER EDIPartyName.
     * @exception IOException on error.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public EDIPartyName(DerValue derValue) throws IOException {
        DerInputStream in = new DerInputStream(derValue.toByteArray());
        DerValue[] seq = in.getSequence(2);

        int len = seq.length;
        if (len < 1 || len > 2)
            throw new IOException("Invalid encoding of EDIPartyName");

        for (DerValue value : seq) {
            DerValue opt = value;
            if (opt.isContextSpecific(TAG_ASSIGNER) &&
                    !opt.isConstructed()) {
                if (assigner != null)
                    throw new IOException("Duplicate nameAssigner found in"
                            + " EDIPartyName");
                opt = opt.data.getDerValue();
                assigner = opt.getAsString();
            }
            if (opt.isContextSpecific(TAG_PARTYNAME) &&
                    !opt.isConstructed()) {
                if (party != null)
                    throw new IOException("Duplicate partyName found in"
                            + " EDIPartyName");
                opt = opt.data.getDerValue();
                party = opt.getAsString();
            }
        }
    }

    /**
     * Return the type of the GeneralName.
     */
    public int getType() {
        return (NAME_EDI);
    }

    /**
     * Encode the EDI party name into the DerOutputStream.
     *
     * @param out the DER stream to encode the EDIPartyName to.
     * @exception IOException on encoding errors.
     */
    public void encode(DerOutputStream out) throws IOException {
        DerOutputStream tagged = new DerOutputStream();
        DerOutputStream tmp = new DerOutputStream();

        if (assigner != null) {
            DerOutputStream tmp2 = new DerOutputStream();
            // XXX - shd check is chars fit into PrintableString
            tmp2.putPrintableString(assigner);
            tagged.write(DerValue.createTag(DerValue.TAG_CONTEXT,
                                 false, TAG_ASSIGNER), tmp2);
        }
        if (party == null)
            throw  new IOException("Cannot have null partyName");

        // XXX - shd check is chars fit into PrintableString
        tmp.putPrintableString(party);
        tagged.write(DerValue.createTag(DerValue.TAG_CONTEXT,
                                 false, TAG_PARTYNAME), tmp);

        out.write(DerValue.tag_Sequence, tagged);
    }

    /*
     * Compare this EDIPartyName with another.  Does a byte-string
     * comparison without regard to type of the partyName and
     * the assignerName.
     *
     * @returns true if the two names match
     */
    public boolean equals(Object other) {
        if (!(other instanceof EDIPartyName))
            return false;
        String otherAssigner = ((EDIPartyName)other).assigner;
        if (this.assigner == null) {
            if (otherAssigner != null)
                return false;
        } else {
            if (!(this.assigner.equals(otherAssigner)))
                return false;
        }
        String otherParty = ((EDIPartyName)other).party;
        if (this.party == null) {
            return otherParty == null;
        } else {
            return this.party.equals(otherParty);
        }
    }

    /**
     * Returns the hash code value for this EDIPartyName.
     *
     * @return a hash code value.
     */
    public int hashCode() {
        if (myhash == -1) {
            myhash = 37 + party.hashCode();
            if (assigner != null) {
                myhash = 37 * myhash + assigner.hashCode();
            }
        }
        return myhash;
    }

    /**
     * Return the printable string.
     */
    @NonNull
    public String toString() {
        return ("EDIPartyName: " +
                 ((assigner == null) ? "" :
                   ("  nameAssigner = " + assigner + ","))
                 + "  partyName = " + party);
    }

    /*
     * Return constraint type:<ul>
     *   <li>NAME_DIFF_TYPE = -1: input name is different type from name (i.e. does not constrain)
     *   <li>NAME_MATCH = 0: input name matches name
     *   <li>NAME_NARROWS = 1: input name narrows name
     *   <li>NAME_WIDENS = 2: input name widens name
     *   <li>NAME_SAME_TYPE = 3: input name does not match or narrow name, but is same type
     * </ul>.  These results are used in checking NameConstraints during
     * certification path verification.
     *
     * @param inputName to be checked for being constrained
     * @returns constraint type above
     * @throws UnsupportedOperationException if name is same type, but comparison operations are
     *          not supported for this name type.
     */
    public int constrains(GeneralNameInterface inputName) throws UnsupportedOperationException {
        int constraintType;
        if (inputName == null)
            constraintType = NAME_DIFF_TYPE;
        else if (inputName.getType() != NAME_EDI)
            constraintType = NAME_DIFF_TYPE;
        else {
            throw new UnsupportedOperationException("Narrowing, widening, and matching of names not supported for EDIPartyName");
        }
        return constraintType;
    }

    /*
     * Return subtree depth of this name for purposes of determining
     * NameConstraints minimum and maximum bounds and for calculating
     * path lengths in name subtrees.
     *
     * @returns distance of name from root
     * @throws UnsupportedOperationException if not supported for this name type
     */
    public int subtreeDepth() throws UnsupportedOperationException {
        throw new UnsupportedOperationException("subtreeDepth() not supported for EDIPartyName");
    }

}