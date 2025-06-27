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

package org.apache.wss4j.common.saml.dom;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.w3c.dom.Element;

/**
 * A Callback Handler implementation for a SAML 1.1 assertion. Rather than create a set of beans
 * that SamlAssertionWrapper will use to create a SAML Assertion, it sets a DOM Element directly on
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
        for (Callback callback : callbacks) {
            if (callback instanceof SAMLCallback) {
                SAMLCallback samlCallback = (SAMLCallback) callback;
                Element assertionElement;
                try {
                    assertionElement = getSAMLAssertion();
                } catch (Exception e) {
                    throw new IOException(e.getMessage());
                }
                samlCallback.setAssertionElement(assertionElement);

            } else {
                throw new UnsupportedCallbackException(callback, "Unrecognized Callback");
            }
        }
    }

    /**
     * Mock up a SAML Assertion by using another SAMLCallbackHandler
     * @throws Exception
     */
    private Element getSAMLAssertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setIssuer(issuer);
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);

        SamlAssertionWrapper samlAssertionWrapper = new SamlAssertionWrapper(samlCallback);

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        return samlAssertionWrapper.toDOM(factory.newDocumentBuilder().newDocument());
    }

}
