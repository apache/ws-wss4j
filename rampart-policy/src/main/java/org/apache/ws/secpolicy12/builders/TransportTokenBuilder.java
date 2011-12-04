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
import org.apache.ws.secpolicy.model.TransportToken;

import javax.xml.namespace.QName;
import java.util.Iterator;
import java.util.List;

public class TransportTokenBuilder implements AssertionBuilder<OMElement> {

    public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {
        TransportToken transportToken = new TransportToken(SPConstants.SP_V12);
        Policy policy = PolicyEngine.getPolicy(element.getFirstElement());
        policy = (Policy) policy.normalize(false);

        for (Iterator iterator = policy.getAlternatives(); iterator.hasNext();) {
            processAlternative((List) iterator.next(), transportToken);
            break; // since there should be only one alternative
        }

        return transportToken;
    }

    public QName[] getKnownElements() {
        return new QName[] {SP12Constants.TRANSPORT_TOKEN};
    }

    private void processAlternative(List assertions, TransportToken parent) {
        for (Iterator iterator = assertions.iterator(); iterator.hasNext();) {
            Assertion primtive = (Assertion) iterator.next();
            QName qname = primtive.getName();
                if(SP12Constants.HTTPS_TOKEN.equals(qname)){
                    parent.setToken((HttpsToken)primtive);
            }
        }
    }
}
