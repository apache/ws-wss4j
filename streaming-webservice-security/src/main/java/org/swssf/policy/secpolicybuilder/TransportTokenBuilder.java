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
package org.swssf.policy.secpolicybuilder;

import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.neethi.builders.xml.XmlPrimtiveAssertion;
import org.swssf.policy.secpolicy.*;
import org.swssf.policy.secpolicy.model.HttpsToken;
import org.swssf.policy.secpolicy.model.TransportToken;

import javax.xml.namespace.QName;
import java.util.Iterator;
import java.util.List;

/**
 * class lent from apache rampart
 */
public class TransportTokenBuilder implements AssertionBuilder {

    private static final QName[] KNOWN_ELEMENTS = new QName[]{
            SP11Constants.TRANSPORT_TOKEN,
            SP12Constants.TRANSPORT_TOKEN,
            SP13Constants.TRANSPORT_TOKEN
    };

    public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {

        SPConstants spConstants = PolicyUtil.getSPVersion(element.getQName().getNamespaceURI());

        TransportToken transportToken = new TransportToken(spConstants);

        Policy policy = PolicyEngine.getPolicy(element.getFirstElement());
        policy = (Policy) policy.normalize(false);

        for (Iterator iterator = policy.getAlternatives(); iterator.hasNext(); ) {
            processAlternative((List) iterator.next(), transportToken, spConstants);
            break; // since there should be only one alternative
        }

        return transportToken;
    }

    public QName[] getKnownElements() {
        return KNOWN_ELEMENTS;
    }

    private void processAlternative(List assertions, TransportToken parent, SPConstants spConstants) {

        for (Iterator iterator = assertions.iterator(); iterator.hasNext(); ) {
            XmlPrimtiveAssertion primtive = (XmlPrimtiveAssertion) iterator.next();
            QName qname = primtive.getName();

            if (spConstants.getHttpsToken().equals(qname)) {
                HttpsToken httpsToken = new HttpsToken(spConstants);

                OMElement element = primtive.getValue().getFirstChildWithName(SPConstants.POLICY);

                if (element != null) {
                    OMElement child = element.getFirstElement();
                    if (child != null) {
                        if (spConstants.getHttpBasicAuthentication().equals(child.getQName())) {
                            httpsToken.setHttpBasicAuthentication(true);
                        } else if (spConstants.getHttpDigestAuthentication().equals(child.getQName())) {
                            httpsToken.setHttpDigestAuthentication(true);
                        } else if (spConstants.getRequireClientCertificate().equals(child.getQName())) {
                            httpsToken.setRequireClientCertificate(true);
                        }
                    }
                }

                parent.setToken(httpsToken);
            }
        }
    }
}
