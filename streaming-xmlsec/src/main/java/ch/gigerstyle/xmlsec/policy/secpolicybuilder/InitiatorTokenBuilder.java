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
package ch.gigerstyle.xmlsec.policy.secpolicybuilder;

import ch.gigerstyle.xmlsec.policy.secpolicy.*;
import ch.gigerstyle.xmlsec.policy.secpolicy.model.InitiatorToken;
import ch.gigerstyle.xmlsec.policy.secpolicy.model.Token;
import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.neethi.builders.AssertionBuilder;

import javax.xml.namespace.QName;
import java.util.Iterator;
import java.util.List;

/**
 * class lent from apache rampart
 */
public class InitiatorTokenBuilder implements AssertionBuilder {

    private static final QName[] KNOWN_ELEMENTS = new QName[]{
            SP11Constants.INITIATOR_TOKEN,
            SP12Constants.INITIATOR_TOKEN,
            SP13Constants.INITIATOR_TOKEN
    };

    public Assertion build(OMElement element, AssertionBuilderFactory factory)
            throws IllegalArgumentException {

        SPConstants spConstants = PolicyUtil.getSPVersion(element.getQName().getNamespaceURI());

        InitiatorToken initiatorToken = new InitiatorToken(spConstants);

        Policy policy = PolicyEngine.getPolicy(element.getFirstElement());
        policy = (Policy) policy.normalize(false);

        for (Iterator iterator = policy.getAlternatives(); iterator.hasNext();) {
            processAlternative((List) iterator.next(), initiatorToken);
            break; // TODO process all the token that must be set ..
        }

        return initiatorToken;
    }

    private void processAlternative(List assertions, InitiatorToken parent) {

        Object token;

        for (Iterator iterator = assertions.iterator(); iterator.hasNext();) {
            token = iterator.next();

            if (token instanceof Token) {
                parent.setInitiatorToken((Token) token);
            }
        }
    }

    public QName[] getKnownElements() {
        return KNOWN_ELEMENTS;
    }

}
