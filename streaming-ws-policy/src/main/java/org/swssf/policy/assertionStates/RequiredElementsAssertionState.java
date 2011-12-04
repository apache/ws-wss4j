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
package org.swssf.policy.assertionStates;

import org.apache.ws.secpolicy.AssertionState;
import org.apache.ws.secpolicy.WSSPolicyException;
import org.apache.ws.secpolicy.model.AbstractSecurityAssertion;
import org.apache.ws.secpolicy.model.RequiredElements;
import org.apache.ws.secpolicy.model.XPath;
import org.swssf.policy.Assertable;
import org.swssf.wss.securityEvent.RequiredElementSecurityEvent;
import org.swssf.wss.securityEvent.SecurityEvent;

import javax.xml.namespace.QName;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class RequiredElementsAssertionState extends AssertionState implements Assertable {

    private Map<QName, Boolean> elements = new HashMap<QName, Boolean>();

    public RequiredElementsAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);

        RequiredElements requiredElements = (RequiredElements) assertion;
        for (int i = 0; i < requiredElements.getXPaths().size(); i++) {
            XPath xPath = requiredElements.getXPaths().get(i);
            String[] xPathElements = xPath.getXPath().split("/");
            String[] xPathElement = xPathElements[xPathElements.length - 1].split(":");
            if (xPathElement.length == 2) {
                String ns = xPath.getPrefixNamespaceMap().get(xPathElement[0]);
                if (ns == null) {
                    throw new IllegalArgumentException("Namespace not declared");
                }
                elements.put(new QName(ns, xPathElement[1]), Boolean.FALSE);
            } else {
                elements.put(new QName(xPathElement[1]), Boolean.FALSE);
            }
        }
    }

    @Override
    public SecurityEvent.Event[] getSecurityEventType() {
        return new SecurityEvent.Event[]{
                SecurityEvent.Event.RequiredElement
        };
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) throws WSSPolicyException {
        RequiredElementSecurityEvent requiredElementSecurityEvent = (RequiredElementSecurityEvent) securityEvent;
        //todo better matching until we have a streaming xpath evaluation engine (work in progress)

        Iterator<Map.Entry<QName, Boolean>> elementMapIterator = elements.entrySet().iterator();
        while (elementMapIterator.hasNext()) {
            Map.Entry<QName, Boolean> next = elementMapIterator.next();
            QName qName = next.getKey();
            if (qName.equals(requiredElementSecurityEvent.getElement())) {
                next.setValue(Boolean.TRUE);
                break;
            }
        }
        //if we return false here other required elements will trigger a PolicyViolationException
        return true;
    }

    @Override
    public boolean isAsserted() {
        Iterator<Map.Entry<QName, Boolean>> elementMapIterator = elements.entrySet().iterator();
        while (elementMapIterator.hasNext()) {
            Map.Entry<QName, Boolean> next = elementMapIterator.next();
            if (Boolean.FALSE.equals(next.getValue())) {
                setErrorMessage("Element " + next.getKey().toString() + " must be present");
                return false;
            }
        }
        return true;
    }
}
