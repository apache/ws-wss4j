/*
 * Copyright 2001-2004 The Apache Software Foundation.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ws.secpolicy12.builders;

import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.ws.secpolicy.SP12Constants;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.model.HttpsToken;

import javax.xml.namespace.QName;
import java.util.Iterator;
import java.util.List;

/**
 * This is a standard assertion builder implementation for the https token 
 * as specified by the ws security policy 1.2 specification. In order for this builder to be used
 * it is required that the security policy namespace uri is {@link SP12Constants#SP_NS} 
 * The builder will handle
 * <ul>
 *  <li><code>HttpBasicAuthentication</code></li>
 *  <li><code>HttpDigestAuthentication</code></li>
 *  <li><code>RequireClientCertificate</code></li>
 * </ul> 
 * alternatives in the HttpsToken considering both cases whether the policy is normalized or not.
 * 
 */
public class HttpsTokenBuilder implements AssertionBuilder<OMElement> {
    
    /**
     * {@inheritDoc}
     */
    public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {
        HttpsToken httpsToken = new HttpsToken(SPConstants.SP_V12);

        if (element.getFirstElement()!= null) {
            Policy policy = PolicyEngine.getPolicy(element.getFirstElement());
            policy = (Policy) policy.normalize(false);

            for (Iterator iterator = policy.getAlternatives(); iterator.hasNext();) {
                processAlternative((List) iterator.next(), httpsToken);
                break; // since there should be only one alternative
            }
        }

        return httpsToken;
    }

    /**
     * {@inheritDoc}
     */
    public QName[] getKnownElements() {
        return new QName[] {SP12Constants.HTTPS_TOKEN};
    }
    
    /**
     * Process policy alternatives inside the HttpsToken element.
     * Essentially this method will search for<br>
     * <ul>
     *  <li><code>HttpBasicAuthentication</code></li>
     *  <li><code>HttpDigestAuthentication</code></li>
     *  <li><code>RequireClientCertificate</code></li>
     * </ul>
     * elements.
     * @param assertions the list of assertions to be searched through.
     * @param parent the https token, that is to be populated with retrieved data.
     */
    private void processAlternative(List assertions, HttpsToken parent) {
        
        for (Iterator iterator = assertions.iterator(); iterator.hasNext();) {
            Assertion primtive = (Assertion) iterator.next();
            QName qname = primtive.getName();
            
            if (qname != null) {
                if (SP12Constants.HTTP_BASIC_AUTHENTICATION.equals(qname)) {
                    parent.setHttpBasicAuthentication(true);
                } else if (SP12Constants.HTTP_DIGEST_AUTHENTICATION.equals(qname)) {
                    parent.setHttpDigestAuthentication(true);
                } else if (SP12Constants.REQUIRE_CLIENT_CERTIFICATE.equals(qname)) {
                    parent.setRequireClientCertificate(true);
                }
            }
        }
    }
}
