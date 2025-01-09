/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.wss4j.common.token;

import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.crypto.BouncyCastleUtils;
import org.apache.wss4j.common.util.DOM2Writer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.cert.X509Certificate;


/**
 * An X.509 SKI token.
 */
public final class DOMX509SKI {
    private final Element element;

    /**
     * Constructor.
     */
    public DOMX509SKI(Document doc, X509Certificate remoteCertificate) {
        element = doc.createElementNS(WSS4JConstants.SIG_NS, "ds:X509SKI");

        element.setTextContent(
                org.apache.xml.security.utils.XMLUtils.encodeToString(BouncyCastleUtils.getSubjectKeyIdentifierBytes(remoteCertificate)
        ));
    }

    /**
     * return the dom element.
     *
     * @return the dom element.
     */
    public Element getElement() {
        return element;
    }

    /**
     * return the string representation of the token.
     *
     * @return the string representation of the token.
     */
    public String toString() {
        return DOM2Writer.nodeToString(element);
    }

}