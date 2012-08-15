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

package org.apache.ws.security.common;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.saml.ext.SAMLCallback;
import org.apache.ws.security.saml.ext.SAMLParms;
import org.apache.ws.security.saml.ext.builder.SAML1Constants;
import org.w3c.dom.Element;

/**
 * A Callback Handler implementation for a SAML 1.1 assertion. Rather than create a set of beans
 * that AssertionWrapper will use to create a SAML Assertion, it sets a DOM Element directly on
 * the SAMLCallback object.
 */
public class SAMLElementCallbackHandler extends AbstractSAMLCallbackHandler {
    
    public SAMLElementCallbackHandler() {
        subjectName = "uid=joe,ou=people,ou=saml-demo,o=example.com";
        subjectQualifier = "www.example.com";
        confirmationMethod = SAML1Constants.CONF_SENDER_VOUCHES;
    }
    
    public void handle(Callback[] callbacks)
        throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof SAMLCallback) {
                SAMLCallback callback = (SAMLCallback) callbacks[i];
                Element assertionElement;
                try {
                    assertionElement = getSAMLAssertion();
                } catch (Exception e) {
                    throw new IOException(e.getMessage());
                }
                callback.setAssertionElement(assertionElement);
                
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }
    
    /**
     * Mock up a SAML Assertion by using another SAMLCallbackHandler
     * @throws Exception 
     */
    private Element getSAMLAssertion() throws Exception {
        SAMLParms parms = new SAMLParms();
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setIssuer(issuer);
        parms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertionWrapper = new AssertionWrapper(parms);
        
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        return assertionWrapper.toDOM(factory.newDocumentBuilder().newDocument());
    }
    
}
