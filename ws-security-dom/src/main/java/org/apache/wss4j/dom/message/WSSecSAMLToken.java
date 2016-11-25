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

import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.util.WSSecurityUtil;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Builds a WS SAML Assertion and inserts it into the SOAP Envelope. Refer to
 * the WS specification, SAML Token profile
 */
public class WSSecSAMLToken extends WSSecBase {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(WSSecSAMLToken.class);

    private SamlAssertionWrapper saml;

    private Element samlElement;

    public WSSecSAMLToken(WSSecHeader securityHeader) {
        super(securityHeader);
    }
    
    public WSSecSAMLToken(Document doc) {
        super(doc);
    }

    /**
     * Creates a SAML token.
     *
     * The method prepares and initializes a WSSec UsernameToken structure after
     * the relevant information was set. A Before calling
     * <code>prepare()</code> all parameters such as user, password,
     * passwordType etc. must be set. A complete <code>UsernameToken</code> is
     * constructed.
     */
    public void prepare(SamlAssertionWrapper samlAssertion) {
        saml = samlAssertion;
    }

    /**
     * Prepends the SAML Assertion to the elements already in the
     * Security header.
     *
     * The method can be called any time after <code>prepare()</code>.
     * This allows to insert the SAML assertion at any position in the
     * Security header.
     *
     */
    public void prependToHeader() {
        try {
            Element element = getElement();
            if (element != null) {
                Element securityHeaderElement = getSecurityHeader().getSecurityHeaderElement();
                WSSecurityUtil.prependChildElement(securityHeaderElement, element);
            }
        } catch (WSSecurityException ex) {
            throw new RuntimeException(ex.toString(), ex);
        }
    }

    public Element getElement() throws WSSecurityException {
        if (samlElement != null) {
            return samlElement;
        }
        if (saml == null) {
            return null;
        }
        samlElement = saml.toDOM(getDocument());
        return samlElement;
    }

    /**
     * Get the id generated during <code>prepare()</code>.
     *
     * Returns the the value of wsu:Id attribute of this Timestamp.
     *
     * @return Return the wsu:Id of this token or null if <code>prepareToken()</code>
     * was not called before.
     */
    public String getId() {
        if (saml == null) {
            return null;
        }
        return saml.getId();
    }

    /**
     * Adds a new <code>SAMLAssertion</code> to a soap envelope.
     * <p/>
     * A complete <code>SAMLAssertion</code> is added to the
     * <code>wsse:Security</code> header.
     *
     * @param samlAssertion TODO
     * @return Document with UsernameToken added
     */
    public Document build(SamlAssertionWrapper samlAssertion) {
        LOG.debug("Begin add SAMLAssertion token...");

        prepare(samlAssertion);
        prependToHeader();

        return getDocument();
    }
}
