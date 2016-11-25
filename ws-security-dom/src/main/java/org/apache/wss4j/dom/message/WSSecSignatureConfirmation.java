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

package org.apache.wss4j.dom.message;

import org.apache.wss4j.dom.message.token.SignatureConfirmation;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Builds a WS SignatureConfirmation and inserts it into the SOAP Envelope.
 */
public class WSSecSignatureConfirmation extends WSSecBase {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(WSSecSignatureConfirmation.class);

    private SignatureConfirmation sc;

    private byte[] signatureValue;

    public WSSecSignatureConfirmation(WSSecHeader securityHeader) {
        super(securityHeader);
    }
    
    public WSSecSignatureConfirmation(Document doc) {
        super(doc);
    }

    /**
     * Set the Signature value to store in this SignatureConfirmation.
     *
     * @param signatureValue The Signature value to store in the SignatureConfirmation element
     */
    public void setSignatureValue(byte[] signatureValue) {
        this.signatureValue = signatureValue;
    }


    /**
     * Creates a SignatureConfimation element.
     *
     * The method prepares and initializes a WSSec SignatureConfirmation structure after
     * the relevant information was set. Before calling <code>prepare()</code> the
     * filed <code>signatureValue</code> must be set
     */
    public void prepare() {
        sc = new SignatureConfirmation(getDocument(), signatureValue);
        sc.setID(getIdAllocator().createId("SC-", sc));
    }

    /**
     * Prepends the SignatureConfirmation element to the elements already in the
     * Security header.
     *
     * The method can be called any time after <code>prepare()</code>.
     * This allows to insert the SignatureConfirmation element at any position in the
     * Security header.
     */
    public void prependToHeader() {
        Element securityHeaderElement = getSecurityHeader().getSecurityHeaderElement();
        WSSecurityUtil.prependChildElement(securityHeaderElement, sc.getElement());
    }

    /**
     * Adds a new <code>SignatureConfirmation</code> to a soap envelope.
     *
     * A complete <code>SignatureConfirmation</code> is constructed and added
     * to the <code>wsse:Security</code> header.
     *
     * @param sigVal the Signature value. This will be the content of the "Value" attribute.
     * @return Document with SignatureConfirmation added
     */
    public Document build(byte[] sigVal) {
        LOG.debug("Begin add signature confirmation...");

        signatureValue = sigVal;
        prepare();
        prependToHeader();

        return getDocument();
    }

    /**
     * Get the id generated during <code>prepare()</code>.
     *
     * Returns the the value of wsu:Id attribute of this SignatureConfirmation.
     *
     * @return Return the wsu:Id of this token or null if <code>prepareToken()</code>
     * was not called before.
     */
    public String getId() {
        if (sc == null) {
            return null;
        }
        return sc.getID();
    }

    /**
     * Get the SignatureConfirmation element generated during
     * <code>prepare()</code>.
     *
     * @return Return the SignatureConfirmation element or null if <code>prepare()</code>
     * was not called before.
     */
    public Element getSignatureConfirmationElement() {
        return (sc != null) ? sc.getElement() : null;
    }

}
