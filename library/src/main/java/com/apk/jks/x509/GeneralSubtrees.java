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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.apk.jks.utils.DerOutputStream;

public class GeneralSubtrees implements Cloneable {

    private final List<GeneralSubtree> trees;

    /**
     * The default constructor for the class.
     */
    public GeneralSubtrees() {
        trees = new ArrayList<>();
    }

    private GeneralSubtrees(GeneralSubtrees source) {
        trees = new ArrayList<>(source.trees);
    }

    /**
     * Create the object from the passed DER encoded form.
     *
     * @param val the DER encoded form of the same.
     */
    public GeneralSubtrees(DerValue val) throws IOException {
        this();
        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding of GeneralSubtrees.");
        }
        while (val.data.available() != 0) {
            DerValue opt = val.data.getDerValue();
            GeneralSubtree tree = new GeneralSubtree(opt);
            add(tree);
        }
    }

    public GeneralSubtree get(int index) {
        return trees.get(index);
    }

    public void remove(int index) {
        trees.remove(index);
    }

    public void add(GeneralSubtree tree) {
        if (tree == null) {
            throw new NullPointerException();
        }
        trees.add(tree);
    }

    public boolean contains(GeneralSubtree tree) {
        if (tree == null) {
            throw new NullPointerException();
        }
        return trees.contains(tree);
    }

    public int size() {
        return trees.size();
    }

    @NonNull
    public Object clone() {
        return new GeneralSubtrees(this);
    }

    /**
     * Return a printable string of the GeneralSubtree.
     */
    @NonNull
    public String toString() {
        return "   GeneralSubtrees:\n" + trees.toString() + "\n";
    }

    /*
     * Encode the GeneralSubtrees.
     *
     * @params out the DerOutputStrean to encode this object to.
     */
    public void encode(DerOutputStream out) throws IOException {
        DerOutputStream seq = new DerOutputStream();

        for (int i = 0, n = size(); i < n; i++) {
            get(i).encode(seq);
        }
        out.write(DerValue.tag_Sequence, seq);
    }

    /*
     * Compare two general subtrees by comparing the subtrees
     * of each.
     *
     * @param other GeneralSubtrees to compare to this
     * @returns true if match
     */
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GeneralSubtrees)) {
            return false;
        }
        GeneralSubtrees other = (GeneralSubtrees)obj;
        return this.trees.equals(other.trees);
    }

    public int hashCode() {
        return trees.hashCode();
    }

}