/*
 * Copyright  2003-2005 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.apache.ws.security.message;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.message.token.SignatureConfirmation;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Builds a WS SignatureConfirmation and inserts it into the SOAP Envelope.
 * 
 * @author Werner Dittmann (Werner.Dittmann@t-online.de).
 */

public class WSAddSignatureConfirmation extends WSBaseMessage {
    private static Log log = LogFactory.getLog(WSAddSignatureConfirmation.class
            .getName());

    private SignatureConfirmation sc = null;

    private String id = null;

    /**
     * Constructor.
     */
    public WSAddSignatureConfirmation() {
    }

    /**
     * Constructor.
     * 
     * @param actor
     *            the name of the actor of the <code>wsse:Security</code>
     *            header
     */
    public WSAddSignatureConfirmation(String actor) {
        super(actor);
    }

    /**
     * Constructor.
     * 
     * @param actor
     *            The name of the actor of the <code>wsse:Security</code>
     *            header
     * @param mu
     *            Set <code>mustUnderstand</code> to true or false
     */
    public WSAddSignatureConfirmation(String actor, boolean mu) {
        super(actor, mu);
    }

    /**
     * Adds a new <code>SignatureConfirmation</code> to a soap envelope.
     * 
     * A complete <code>SignatureConfirmation</code> is constructed and added
     * to the <code>wsse:Security</code> header.
     * 
     * @param doc
     *            The SOAP enevlope as W3C document
     * @param sigVal
     *            the Signature value. This will be the content of the "Value"
     *            attribute.
     * @return Document with SignatureConfirmation added
     */
    public Document build(Document doc, byte[] sigVal) {
        log.debug("Begin add signature confirmation...");
        Element securityHeader = insertSecurityHeader(doc);
        sc = new SignatureConfirmation(doc, sigVal);
        if (id != null) {
            sc.setID(id);
        }
        WSSecurityUtil.prependChildElement(doc, securityHeader,
                sc.getElement(), true);
        sc = null;
        return doc;
    }

    /**
     * Set the wsu:Id value of the SignatureConfirmation
     * 
     * @param id
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * Get the wsu:Id value of the SignatureConfirmation
     * 
     * @return Returns the wsu:id value
     */
    public String getId() {
        return id;
    }
}