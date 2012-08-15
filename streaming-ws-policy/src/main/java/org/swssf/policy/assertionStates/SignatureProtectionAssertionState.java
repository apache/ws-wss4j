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
import org.apache.ws.secpolicy.model.AbstractSymmetricAsymmetricBinding;
import org.apache.xml.security.stax.securityEvent.EncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.swssf.policy.Assertable;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSUtils;
import org.swssf.wss.securityEvent.WSSecurityEventConstants;

import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * WSP1.3, 6.4 Signature Protection Property
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SignatureProtectionAssertionState extends AssertionState implements Assertable {

    private final List<List<QName>> elementPaths = new ArrayList<List<QName>>();

    public SignatureProtectionAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
        List<QName> signature11Path = new LinkedList<QName>();
        signature11Path.addAll(WSSConstants.SOAP_11_HEADER_PATH);
        signature11Path.add(WSSConstants.TAG_wsse_Security);
        signature11Path.add(WSSConstants.TAG_dsig_Signature);
        elementPaths.add(signature11Path);

        List<QName> signatureConfirmation11Path = new LinkedList<QName>();
        signatureConfirmation11Path.addAll(WSSConstants.SOAP_11_HEADER_PATH);
        signatureConfirmation11Path.add(WSSConstants.TAG_wsse_Security);
        signatureConfirmation11Path.add(WSSConstants.TAG_wsse11_SignatureConfirmation);
        elementPaths.add(signatureConfirmation11Path);
    }

    @Override
    public SecurityEventConstants.Event[] getSecurityEventType() {
        return new SecurityEventConstants.Event[]{
                WSSecurityEventConstants.EncryptedElement
        };
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) throws WSSPolicyException {
        EncryptedElementSecurityEvent encryptedElementSecurityEvent = (EncryptedElementSecurityEvent) securityEvent;
        AbstractSymmetricAsymmetricBinding abstractSymmetricAsymmetricBinding = (AbstractSymmetricAsymmetricBinding) getAssertion();
        //todo better matching until we have a streaming xpath evaluation engine (work in progress)

        Iterator<List<QName>> pathElementsIterator = elementPaths.iterator();
        while (pathElementsIterator.hasNext()) {
            List<QName> qNameList = pathElementsIterator.next();
            if (WSSUtils.pathMatches(qNameList, encryptedElementSecurityEvent.getElementPath(), true, false)) {
                if (encryptedElementSecurityEvent.isEncrypted()) {
                    if (abstractSymmetricAsymmetricBinding.isEncryptSignature()) {
                        setAsserted(true);
                        return true;
                    } else {
                        setAsserted(false);
                        setErrorMessage("Element " + WSSUtils.pathAsString(encryptedElementSecurityEvent.getElementPath()) + " must not be encrypted");
                        return false;
                    }
                } else {
                    if (abstractSymmetricAsymmetricBinding.isEncryptSignature()) {
                        setAsserted(false);
                        setErrorMessage("Element " + WSSUtils.pathAsString(encryptedElementSecurityEvent.getElementPath()) + " must be encrypted");
                        return false;
                    } else {
                        setAsserted(true);
                        return true;
                    }
                }
            }
        }
        //if we return false here other encrypted elements will trigger a PolicyViolationException
        return true;
    }
}
