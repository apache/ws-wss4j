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
import org.apache.ws.secpolicy.model.ContentEncryptedElements;
import org.apache.ws.secpolicy.model.XPath;
import org.apache.xml.security.stax.securityEvent.ContentEncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.swssf.policy.Assertable;
import org.swssf.policy.PolicyUtils;
import org.swssf.wss.ext.WSSUtils;
import org.swssf.wss.securityEvent.WSSecurityEventConstants;

import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * WSP1.3, 4.2.3 ContentEncryptedElements Assertion
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class ContentEncryptedElementsAssertionState extends AssertionState implements Assertable {

    private final List<List<QName>> pathElements = new ArrayList<List<QName>>();

    public ContentEncryptedElementsAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);

        ContentEncryptedElements contentEncryptedElements = (ContentEncryptedElements) assertion;
        for (int i = 0; i < contentEncryptedElements.getXPaths().size(); i++) {
            XPath xPath = contentEncryptedElements.getXPaths().get(i);
            List<QName> elements = PolicyUtils.getElementPath(xPath);
            pathElements.add(elements);
        }
    }

    @Override
    public SecurityEventConstants.Event[] getSecurityEventType() {
        return new SecurityEventConstants.Event[]{
                WSSecurityEventConstants.ContentEncrypted
        };
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) throws WSSPolicyException {
        ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent = (ContentEncryptedElementSecurityEvent) securityEvent;

        Iterator<List<QName>> pathElementIterator = pathElements.iterator();
        while (pathElementIterator.hasNext()) {
            List<QName> pathElements = pathElementIterator.next();
            if (WSSUtils.pathMatches(pathElements, contentEncryptedElementSecurityEvent.getElementPath(), true, false)) {
                if (contentEncryptedElementSecurityEvent.isEncrypted()) {
                    setAsserted(true);
                    return true;
                } else {
                    //an element must be encrypted but isn't
                    setAsserted(false);
                    setErrorMessage("Content of element " + WSSUtils.pathAsString(contentEncryptedElementSecurityEvent.getElementPath()) + " must be encrypted");
                    return false;
                }
            }
        }
        //if we return false here other encrypted elements will trigger a PolicyViolationException
        return true;
    }
}
