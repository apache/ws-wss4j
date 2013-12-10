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
package org.apache.wss4j.policy.stax.assertionStates;

import org.apache.wss4j.policy.AssertionState;
import org.apache.wss4j.policy.WSSPolicyException;
import org.apache.wss4j.policy.model.AbstractSecurityAssertion;
import org.apache.wss4j.policy.model.AbstractSymmetricAsymmetricBinding;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.securityEvent.EncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;
import org.apache.xml.security.stax.securityToken.SecurityToken;
import org.apache.wss4j.policy.stax.Assertable;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSUtils;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;

import javax.xml.namespace.QName;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * WSP1.3, 6.4 Signature Protection Property
 */
public class SignatureProtectionAssertionState extends AssertionState implements Assertable {

    private final ArrayList<EncryptedElementSecurityEvent> encryptedElementEvents = 
        new ArrayList<EncryptedElementSecurityEvent>();
    private final ArrayList<TokenSecurityEvent<? extends SecurityToken>> tokenSecurityEvents =
            new ArrayList<TokenSecurityEvent<? extends SecurityToken>>();
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
                WSSecurityEventConstants.EncryptedElement,
                WSSecurityEventConstants.EncryptedKeyToken,
                WSSecurityEventConstants.IssuedToken,
                WSSecurityEventConstants.KerberosToken,
                SecurityEventConstants.KeyValueToken,
                WSSecurityEventConstants.RelToken,
                WSSecurityEventConstants.SamlToken,
                WSSecurityEventConstants.SecurityContextToken,
                WSSecurityEventConstants.UsernameToken,
                SecurityEventConstants.X509Token,
                WSSecurityEventConstants.Operation,
        };
    }
    
    @Override
    public boolean assertEvent(SecurityEvent securityEvent) throws WSSPolicyException {
        if (securityEvent instanceof EncryptedElementSecurityEvent) {
            EncryptedElementSecurityEvent encryptedElementSecurityEvent = 
                (EncryptedElementSecurityEvent) securityEvent;
            // Store all matching Signature/SignatureConfirmation Elements
            Iterator<List<QName>> pathElementsIterator = elementPaths.iterator();
            while (pathElementsIterator.hasNext()) {
                List<QName> qNameList = pathElementsIterator.next();
                if (WSSUtils.pathMatches(qNameList, encryptedElementSecurityEvent.getElementPath(), true, false)) {
                    encryptedElementEvents.add(encryptedElementSecurityEvent);
                }
            }
        } else if (securityEvent instanceof TokenSecurityEvent) {
            @SuppressWarnings("unchecked")
            TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent 
                = (TokenSecurityEvent<? extends SecurityToken>) securityEvent;
            tokenSecurityEvents.add(tokenSecurityEvent);
        }
        
        return true;
    }
    
    @Override
    public boolean isAsserted() {
        clearErrorMessage();
        
        // If we only have one (main) Signature, then check that it matches the policy
        if (encryptedElementEvents.size() == 1) {
            return testEncryptedSignature(encryptedElementEvents.get(0));
        } else if (encryptedElementEvents.size() > 1) {
            // Otherwise we only check the policy for the main Signature
            String endorsingSignatureId = findEndorsingSignatureId();
            for (EncryptedElementSecurityEvent encryptedElementSecurityEvent : encryptedElementEvents) {
                String elementId = encryptedElementSecurityEvent.getCorrelationID();
                if (endorsingSignatureId != null && endorsingSignatureId.equals(elementId)) {
                    // Skip this Endorsing Signature
                    continue;
                }
                if (!testEncryptedSignature(encryptedElementSecurityEvent)) {
                    return false;
                }
            }
        }

        return true;
    }
    
    private String findEndorsingSignatureId() {
        for (int i = 0; i < tokenSecurityEvents.size(); i++) {
            TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent = tokenSecurityEvents.get(i);
            try {
                SecurityToken securityToken = 
                    getEffectiveSignatureToken(tokenSecurityEvent.getSecurityToken());
                if (isSignatureToken(securityToken) && !isMainSignatureToken(securityToken)) {
                    return tokenSecurityEvent.getCorrelationID();
                }
            } catch (XMLSecurityException e) {
                // Just return null here
                return null;
            }
        }
        return null;
    }
    
    private boolean isSignatureToken(SecurityToken securityToken) {
        List<WSSecurityTokenConstants.TokenUsage> tokenUsages = securityToken.getTokenUsages();
        for (int i = 0; i < tokenUsages.size(); i++) {
            WSSecurityTokenConstants.TokenUsage tokenUsage = tokenUsages.get(i);
            if (WSSecurityTokenConstants.TokenUsage_Signature.equals(tokenUsage)
                    || WSSecurityTokenConstants.TokenUsage_MainSignature.equals(tokenUsage)
                    || tokenUsage.getName().contains("Endorsing")) {
                return true;
            }
        }
        return false;
    }
    
    private boolean isMainSignatureToken(SecurityToken securityToken) throws XMLSecurityException {
        SecurityToken rootToken = WSSUtils.getRootToken(securityToken);
        List<WSSecurityTokenConstants.TokenUsage> tokenUsages = rootToken.getTokenUsages();
        return tokenUsages.contains(WSSecurityTokenConstants.TokenUsage_MainSignature);
    }
    
    private SecurityToken getEffectiveSignatureToken(SecurityToken securityToken) throws XMLSecurityException {
        SecurityToken tmp = WSSUtils.getRootToken(securityToken);
        List<? extends SecurityToken> wrappedTokens = tmp.getWrappedTokens();
        for (int i = 0; i < wrappedTokens.size(); i++) {
            SecurityToken token = wrappedTokens.get(i);
            if (isSignatureToken(token)) {
                //WSP 1.3, 6.5 [Token Protection] Property: Note that in cases where derived keys are used
                //the 'main' token, and NOT the derived key token, is covered by the signature.
                if (WSSecurityTokenConstants.DerivedKeyToken.equals(token.getTokenType())) {
                    return tmp;
                }
                tmp = token;
            }
        }
        return tmp;
    }

    private boolean testEncryptedSignature(EncryptedElementSecurityEvent encryptedElementSecurityEvent) {
        AbstractSymmetricAsymmetricBinding abstractSymmetricAsymmetricBinding = 
            (AbstractSymmetricAsymmetricBinding) getAssertion();
        
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
