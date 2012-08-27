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
package org.apache.ws.security.policy.stax.assertionStates;

import org.apache.neethi.Assertion;
import org.apache.ws.security.policy.AssertionState;
import org.apache.ws.security.policy.WSSPolicyException;
import org.apache.ws.security.policy.model.AbstractSymmetricAsymmetricBinding;
import org.apache.ws.security.policy.stax.Assertable;
import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.ws.security.stax.ext.WSSUtils;
import org.apache.ws.security.stax.securityEvent.WSSecurityEventConstants;
import org.apache.xml.security.stax.ext.SecurityToken;
import org.apache.xml.security.stax.ext.XMLSecurityException;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.SignedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;

import javax.xml.namespace.QName;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * WSP1.3, 6.5 Token Protection Property
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class TokenProtectionAssertionState extends AssertionState implements Assertable {

    private final List<SignedElementSecurityEvent> signedElementEvents = new LinkedList<SignedElementSecurityEvent>();
    private final List<TokenSecurityEvent> tokenSecurityEvents = new LinkedList<TokenSecurityEvent>();

    public TokenProtectionAssertionState(Assertion assertion, boolean initialAssertionState) {
        super(assertion, initialAssertionState);
    }

    @Override
    public SecurityEventConstants.Event[] getSecurityEventType() {
        return new SecurityEventConstants.Event[]{
                SecurityEventConstants.SignedElement,
                WSSecurityEventConstants.EncryptedKeyToken,
                WSSecurityEventConstants.IssuedToken,
                WSSecurityEventConstants.KerberosToken,
                SecurityEventConstants.KeyValueToken,
                WSSecurityEventConstants.RelToken,
                WSSecurityEventConstants.SamlToken,
                WSSecurityEventConstants.SecureConversationToken,
                WSSecurityEventConstants.SecurityContextToken,
                WSSecurityEventConstants.SpnegoContextToken,
                WSSecurityEventConstants.UsernameToken,
                SecurityEventConstants.X509Token,
                WSSecurityEventConstants.Operation,
        };
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) throws WSSPolicyException, XMLSecurityException {

        AbstractSymmetricAsymmetricBinding abstractSymmetricAsymmetricBinding = (AbstractSymmetricAsymmetricBinding) getAssertion();
        boolean protectTokens = abstractSymmetricAsymmetricBinding.isProtectTokens();

        if (securityEvent instanceof SignedElementSecurityEvent) {
            SignedElementSecurityEvent signedElementSecurityEvent = (SignedElementSecurityEvent) securityEvent;
            if (signedElementSecurityEvent.isSigned()) {
                signedElementEvents.add(signedElementSecurityEvent);
            }
        } else if (securityEvent instanceof TokenSecurityEvent) {
            TokenSecurityEvent tokenSecurityEvent = (TokenSecurityEvent) securityEvent;
            tokenSecurityEvents.add(tokenSecurityEvent);
        } else { //Operation
            Iterator<TokenSecurityEvent> tokenSecurityEventIterator = tokenSecurityEvents.iterator();
            while (tokenSecurityEventIterator.hasNext()) {
                TokenSecurityEvent tokenSecurityEvent = tokenSecurityEventIterator.next();

                SecurityToken securityToken = tokenSecurityEvent.getSecurityToken();
                while (securityToken.getKeyWrappingToken() != null) {
                    securityToken = securityToken.getKeyWrappingToken();
                }

                if (isSignatureToken(securityToken)) {
                    //[WSP1.3_8.9]
                    boolean signsItsSignatureToken = signsItsSignatureToken(securityToken);
                    if (protectTokens && !signsItsSignatureToken) {
                        setAsserted(false);
                        setErrorMessage("Token " + WSSUtils.pathAsString(securityToken.getElementPath()) + " must be signed by its signature.");
                        return false;
                    } else if (!protectTokens && signsItsSignatureToken) {
                        setAsserted(false);
                        setErrorMessage("Token " + WSSUtils.pathAsString(securityToken.getElementPath()) + " must not be signed by its signature.");
                        return false;
                    }
                }

                if (isEndorsingToken(securityToken) && !signsMainSignature(securityToken)) {
                    //[WSP1.3_8.9b]
                    setAsserted(false);
                    setErrorMessage("Token " + WSSUtils.pathAsString(securityToken.getElementPath()) + " must sign the main signature.");
                    return false;
                }

                if (isMainSignatureToken(securityToken) 
                        && !signsSignedSupportingTokens(securityToken)) {
                    setAsserted(false);
                    setErrorMessage("Main signature must sign the Signed*Supporting-Tokens.");
                    return false;
                }
            }
        }
        return true;
    }

    private boolean isSignatureToken(SecurityToken securityToken) {
        List<SecurityToken.TokenUsage> tokenUsages = securityToken.getTokenUsages();
        for (int i = 0; i < tokenUsages.size(); i++) {
            SecurityToken.TokenUsage tokenUsage = tokenUsages.get(i);
            if (tokenUsage == SecurityToken.TokenUsage.Signature
                    || tokenUsage == SecurityToken.TokenUsage.MainSignature
                    || tokenUsage.name().contains("Endorsing")) {
                return true;
            }
        }
        return false;
    }

    private boolean isEndorsingToken(SecurityToken securityToken) {
        List<SecurityToken.TokenUsage> tokenUsages = securityToken.getTokenUsages();
        for (int i = 0; i < tokenUsages.size(); i++) {
            SecurityToken.TokenUsage tokenUsage = tokenUsages.get(i);
            if (tokenUsage.name().contains("Endorsing")) {
                return true;
            }
        }
        return false;
    }

    private boolean isSignedSupportingToken(SecurityToken securityToken) {
        List<SecurityToken.TokenUsage> tokenUsages = securityToken.getTokenUsages();
        for (int i = 0; i < tokenUsages.size(); i++) {
            SecurityToken.TokenUsage tokenUsage = tokenUsages.get(i);
            if (tokenUsage.name().contains("Signed")) {
                return true;
            }
        }
        return false;
    }

    private boolean isMainSignatureToken(SecurityToken securityToken) {
        List<SecurityToken.TokenUsage> tokenUsages = securityToken.getTokenUsages();
        return tokenUsages.contains(SecurityToken.TokenUsage.MainSignature);
    }

    private boolean signsMainSignature(SecurityToken securityToken) throws XMLSecurityException {

        List<QName> signaturePath = new LinkedList<QName>();
        signaturePath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        signaturePath.add(WSSConstants.TAG_dsig_Signature);

        Iterator<SignedElementSecurityEvent> securityEventIterator = signedElementEvents.iterator();
        while (securityEventIterator.hasNext()) {
            SignedElementSecurityEvent signedElementSecurityEvent = securityEventIterator.next();
            if (WSSUtils.pathMatches(signedElementSecurityEvent.getElementPath(), signaturePath, true, false)) {
                SecurityToken signingSecurityToken = signedElementSecurityEvent.getSecurityToken();
                while (signingSecurityToken != null && signingSecurityToken.getKeyWrappingToken() != null) {
                    signingSecurityToken = signingSecurityToken.getKeyWrappingToken();
                }
                //todo ATM me just check if the token signs a signature but we don't know if it's the main signature
                if (signingSecurityToken == securityToken) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean signsItsSignatureToken(SecurityToken securityToken) throws XMLSecurityException {
        Iterator<SignedElementSecurityEvent> securityEventIterator = signedElementEvents.iterator();
        while (securityEventIterator.hasNext()) {
            SignedElementSecurityEvent signedElementSecurityEvent = securityEventIterator.next();
            if (WSSUtils.pathMatches(signedElementSecurityEvent.getElementPath(), securityToken.getElementPath(), false, false)) {

                SecurityToken signingSecurityToken = signedElementSecurityEvent.getSecurityToken();
                while (signingSecurityToken != null && signingSecurityToken.getKeyWrappingToken() != null) {
                    signingSecurityToken = signingSecurityToken.getKeyWrappingToken();
                }

                if (signingSecurityToken == securityToken) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean signsSignedSupportingTokens(SecurityToken securityToken) throws XMLSecurityException {

        List<SecurityToken> signedSupportingTokens = new LinkedList<SecurityToken>();
        List<SignedElementSecurityEvent> signedElements = new LinkedList<SignedElementSecurityEvent>();
        Iterator<TokenSecurityEvent> tokenSecurityEventIterator = tokenSecurityEvents.iterator();
        while (tokenSecurityEventIterator.hasNext()) {
            TokenSecurityEvent tokenSecurityEvent = tokenSecurityEventIterator.next();
            SecurityToken supportingToken = tokenSecurityEvent.getSecurityToken();
            if (isSignedSupportingToken(supportingToken)) {
                if (signedSupportingTokens.contains(supportingToken)) {
                    continue;
                }
                signedSupportingTokens.add(supportingToken);
                List<QName> elementPath = supportingToken.getElementPath();

                boolean found = false;
                Iterator<SignedElementSecurityEvent> signedElementSecurityEventIterator = signedElementEvents.iterator();
                while (signedElementSecurityEventIterator.hasNext()) {
                    SignedElementSecurityEvent signedElementSecurityEvent = signedElementSecurityEventIterator.next();
                    if (WSSUtils.pathMatches(signedElementSecurityEvent.getElementPath(), elementPath, false, false)) {
                        SecurityToken elementSignatureToken = signedElementSecurityEvent.getSecurityToken();
                        while (elementSignatureToken != null && elementSignatureToken.getKeyWrappingToken() != null) {
                            elementSignatureToken = elementSignatureToken.getKeyWrappingToken();
                        }
                        if (signedElementSecurityEvent.getSecurityToken() == securityToken) {
                            if (!signedElements.contains(signedElementSecurityEvent)) {
                                signedElements.add(signedElementSecurityEvent);
                            }
                            found = true;
                        }
                    }
                }
                if (!found) {
                    return false;
                }
            }
        }
        if (signedSupportingTokens.size() > signedElements.size()) {
            return false;
        }

        return true;
    }
}
