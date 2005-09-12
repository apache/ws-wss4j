/*
 * Copyright  2003-2004 The Apache Software Foundation.
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
import org.apache.ws.security.util.WSSecurityUtil;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Builds a WS SAML Assertion and inserts it into the SOAP Envelope. Refer to
 * the WS specification, SAML Token profile
 *
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public class WSSAddSAMLToken extends WSBaseMessage {

    private static Log log = LogFactory.getLog(WSSAddSAMLToken.class.getName());

    /**
     * Constructor.
     */
    public WSSAddSAMLToken() {
    }

    /**
     * Constructor.
     * <p/>
     *
     * @param actor the name of the actor of the <code>wsse:Security</code>
     *              header
     */
    public WSSAddSAMLToken(String actor) {
        super(actor);
    }

    /**
     * Constructor.
     * <p/>
     *
     * @param actor The name of the actor of the <code>wsse:Security</code>
     *              header
     * @param mu    Set <code>mustUnderstand</code> to true or false
     */
    public WSSAddSAMLToken(String actor, boolean mu) {
        super(actor, mu);
    }

    /**
     * Adds a new <code>SAMLAssertion</code> to a soap envelope.
     * <p/>
     * A complete <code>SAMLAssertion</code> is added to the
     * <code>wsse:Security</code> header.
     *
     * @param doc      The SOAP enevlope as W3C document
     * @param assertion TODO
     * @return Document with UsernameToken added
     */
    public Document build(Document doc, SAMLAssertion assertion) {
        log.debug("Begin add SAMLAssertion token...");
        try {
            Element element = (Element) assertion.toDOM(doc);
            Element securityHeader = insertSecurityHeader(doc);
            WSSecurityUtil.prependChildElement(doc,
                    securityHeader,
                    element,
                    true);
        } catch (SAMLException ex) {
            ex.printStackTrace();
            throw new RuntimeException(ex.toString());
        }
        return doc;
    }
}
