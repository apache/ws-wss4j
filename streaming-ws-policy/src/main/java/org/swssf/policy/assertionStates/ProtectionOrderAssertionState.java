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
import org.apache.ws.secpolicy.model.AbstractSecurityAssertion;
import org.apache.ws.secpolicy.model.AbstractSymmetricAsymmetricBinding;
import org.swssf.policy.Assertable;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.TokenSecurityEvent;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */

public class ProtectionOrderAssertionState extends AssertionState implements Assertable {

    boolean firstEvent = true;

    public ProtectionOrderAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public SecurityEvent.Event[] getSecurityEventType() {
        return new SecurityEvent.Event[]{
                SecurityEvent.Event.UsernameToken,
                SecurityEvent.Event.IssuedToken,
                SecurityEvent.Event.X509Token,
                SecurityEvent.Event.KerberosToken,
                SecurityEvent.Event.SpnegoContextToken,
                SecurityEvent.Event.SecurityContextToken,
                SecurityEvent.Event.SecureConversationToken,
                SecurityEvent.Event.SamlToken,
                SecurityEvent.Event.RelToken,
                SecurityEvent.Event.HttpsToken,
                SecurityEvent.Event.KeyValueToken
        };
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) {
        AbstractSymmetricAsymmetricBinding.ProtectionOrder protectionOrder = ((AbstractSymmetricAsymmetricBinding) getAssertion()).getProtectionOrder();
        TokenSecurityEvent tokenSecurityEvent = (TokenSecurityEvent) securityEvent;
        setAsserted(true);
        if (firstEvent) {
            firstEvent = false;
            //we have to invert the logic. When SignBeforeEncrypt is set then the Encryption token appears as first
            //in contrary if EncryptBeforeSign is set then the SignatureToken appears as first. So...:
            if (protectionOrder.equals(AbstractSymmetricAsymmetricBinding.ProtectionOrder.SignBeforeEncrypting)
                    && tokenSecurityEvent.getTokenUsage() == TokenSecurityEvent.TokenUsage.Signature) {
                setAsserted(false);
                setErrorMessage("ProtectionOrder is " + AbstractSymmetricAsymmetricBinding.ProtectionOrder.SignBeforeEncrypting + " but we got " + tokenSecurityEvent.getTokenUsage() + " first");
            } else if (protectionOrder.equals(AbstractSymmetricAsymmetricBinding.ProtectionOrder.EncryptBeforeSigning)
                    && tokenSecurityEvent.getTokenUsage() == TokenSecurityEvent.TokenUsage.Encryption) {
                setAsserted(false);
                setErrorMessage("ProtectionOrder is " + AbstractSymmetricAsymmetricBinding.ProtectionOrder.SignBeforeEncrypting + " but we got " + tokenSecurityEvent.getTokenUsage() + " first");
            }
        }
        return isAsserted();
    }
}
