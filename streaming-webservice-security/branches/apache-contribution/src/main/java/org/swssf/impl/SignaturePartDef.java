/**
 * Copyright 2010, 2011 Marc Giger
 *
 * This file is part of the streaming-webservice-security-framework (swssf).
 *
 * The streaming-webservice-security-framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The streaming-webservice-security-framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the streaming-webservice-security-framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.impl;

/**
 * SignaturePartDef holds information about parts to be signed
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SignaturePartDef {

    private String sigRefId;
    private String digestValue;
    private String transformAlgo;
    private String c14nAlgo;
    private String inclusiveNamespaces;

    public String getSigRefId() {
        return sigRefId;
    }

    public void setSigRefId(String sigRefId) {
        this.sigRefId = sigRefId;
    }

    public String getDigestValue() {
        return digestValue;
    }

    public void setDigestValue(String digestValue) {
        this.digestValue = digestValue;
    }

    public String getTransformAlgo() {
        return transformAlgo;
    }

    public void setTransformAlgo(String transformAlgo) {
        this.transformAlgo = transformAlgo;
    }

    public String getC14nAlgo() {
        return c14nAlgo;
    }

    public void setC14nAlgo(String c14nAlgo) {
        this.c14nAlgo = c14nAlgo;
    }

    public String getInclusiveNamespaces() {
        return inclusiveNamespaces;
    }

    public void setInclusiveNamespaces(String inclusiveNamespaces) {
        this.inclusiveNamespaces = inclusiveNamespaces;
    }
}