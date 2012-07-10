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
package org.swssf.wss.impl;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSUtils;
import org.swssf.wss.ext.WSSecurityException;
import org.swssf.wss.securityEvent.ContentEncryptedElementSecurityEvent;
import org.swssf.wss.securityEvent.EncryptedElementSecurityEvent;
import org.swssf.wss.securityEvent.HttpsTokenSecurityEvent;
import org.swssf.wss.securityEvent.WSSecurityEventConstants;
import org.apache.xml.security.stax.ext.SecurityToken;
import org.apache.xml.security.stax.ext.XMLSecurityException;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SignedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;

import javax.xml.namespace.QName;
import java.util.*;

/**
 * Concrete security context implementation
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class InboundWSSecurityContextImpl extends WSSecurityContextImpl {

    private static final transient Log logger = LogFactory.getLog(WSSecurityContextImpl.class);

    private final Deque<SecurityEvent> securityEventQueue = new ArrayDeque<SecurityEvent>();
    private boolean operationSecurityEventOccured = false;
    private boolean messageEncryptionTokenOccured = false;

    private List<WSSConstants.BSPRule> ignoredBSPRules = Collections.emptyList();

    public synchronized void registerSecurityEvent(SecurityEvent securityEvent) throws XMLSecurityException {

        if (operationSecurityEventOccured) {
            if (!this.messageEncryptionTokenOccured) {
                if (securityEvent instanceof TokenSecurityEvent) {
                    TokenSecurityEvent tokenSecurityEvent = ((TokenSecurityEvent) securityEvent);
                    if (tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(SecurityToken.TokenUsage.Encryption)) {
                        SecurityToken securityToken = tokenSecurityEvent.getSecurityToken();

                        try {
                            while (securityToken.getKeyWrappingToken() != null) {
                                securityToken = securityToken.getKeyWrappingToken();
                            }
                            TokenSecurityEvent newTokenSecurityEvent = WSSUtils.createTokenSecurityEvent(securityToken);
                            setTokenUsage(newTokenSecurityEvent, SecurityToken.TokenUsage.MainEncryption);
                            forwardSecurityEvent(newTokenSecurityEvent);
                        } catch (XMLSecurityException e) {
                            throw new WSSecurityException(e.getMessage(), e);
                        }
                        this.messageEncryptionTokenOccured = true;
                    }
                }
            }

            forwardSecurityEvent(securityEvent);
            return;
        }

        if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.Operation) {
            operationSecurityEventOccured = true;

            try {
                identifySecurityTokenDepenedenciesAndUsage(securityEventQueue);
            } catch (XMLSecurityException e) {
                throw new WSSecurityException(e.getMessage(), e);
            }

            Iterator<SecurityEvent> securityEventIterator = securityEventQueue.descendingIterator();
            while (securityEventIterator.hasNext()) {
                SecurityEvent prevSecurityEvent = securityEventIterator.next();
                forwardSecurityEvent(prevSecurityEvent);
            }
            //forward operation security event
            forwardSecurityEvent(securityEvent);

            securityEventQueue.clear();
            return;
        }

        securityEventQueue.push(securityEvent);
    }

    private void identifySecurityTokenDepenedenciesAndUsage(
            Deque<SecurityEvent> securityEventDeque) throws XMLSecurityException {

        List<TokenSecurityEvent> messageSignatureTokens = Collections.emptyList();
        List<TokenSecurityEvent> messageEncryptionTokens = Collections.emptyList();
        List<TokenSecurityEvent> supportingTokens = Collections.emptyList();
        List<TokenSecurityEvent> signedSupportingTokens = Collections.emptyList();
        List<TokenSecurityEvent> endorsingSupportingTokens = Collections.emptyList();
        List<TokenSecurityEvent> signedEndorsingSupportingTokens = Collections.emptyList();
        List<TokenSecurityEvent> signedEncryptedSupportingTokens = Collections.emptyList();
        List<TokenSecurityEvent> encryptedSupportingTokens = Collections.emptyList();
        List<TokenSecurityEvent> endorsingEncryptedSupportingTokens = Collections.emptyList();
        List<TokenSecurityEvent> signedEndorsingEncryptedSupportingTokens = Collections.emptyList();

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = null;

        List<TokenSecurityEvent> tokenSecurityEvents = new ArrayList<TokenSecurityEvent>();
        Iterator<SecurityEvent> securityEventIterator = securityEventDeque.iterator();
        while (securityEventIterator.hasNext()) {
            SecurityEvent securityEvent = securityEventIterator.next();
            if (securityEvent instanceof TokenSecurityEvent) {
                if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.HttpsToken) {
                    HttpsTokenSecurityEvent actHttpsTokenSecurityEvent = (HttpsTokenSecurityEvent) securityEvent;
                    actHttpsTokenSecurityEvent.getSecurityToken().getTokenUsages().clear();
                    actHttpsTokenSecurityEvent.getSecurityToken().addTokenUsage(SecurityToken.TokenUsage.MainSignature);
                    messageSignatureTokens = addTokenSecurityEvent(actHttpsTokenSecurityEvent, messageSignatureTokens);
                    HttpsTokenSecurityEvent clonedHttpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
                    clonedHttpsTokenSecurityEvent.setAuthenticationType(actHttpsTokenSecurityEvent.getAuthenticationType());
                    clonedHttpsTokenSecurityEvent.setIssuerName(actHttpsTokenSecurityEvent.getIssuerName());
                    clonedHttpsTokenSecurityEvent.setSecurityToken(actHttpsTokenSecurityEvent.getSecurityToken());
                    clonedHttpsTokenSecurityEvent.getSecurityToken().addTokenUsage(SecurityToken.TokenUsage.MainEncryption);
                    messageEncryptionTokens = addTokenSecurityEvent(actHttpsTokenSecurityEvent, messageEncryptionTokens);
                    httpsTokenSecurityEvent = clonedHttpsTokenSecurityEvent;
                    continue;
                }
                tokenSecurityEvents.add((TokenSecurityEvent) securityEvent);
            }
        }

        //search for the root tokens...
        for (int i = 0; i < tokenSecurityEvents.size(); i++) {
            TokenSecurityEvent tokenSecurityEvent = tokenSecurityEvents.get(i);
            SecurityToken securityToken = tokenSecurityEvent.getSecurityToken();
            if (securityToken.getKeyWrappingToken() == null && !containsSecurityToken(supportingTokens, securityToken)) {
                supportingTokens = addTokenSecurityEvent(tokenSecurityEvent, supportingTokens);
            }
        }
        //...and then for the intermediare tokens and create new TokenSecurityEvents if not already there
        for (int i = 0; i < tokenSecurityEvents.size(); i++) {
            TokenSecurityEvent tokenSecurityEvent = tokenSecurityEvents.get(i);
            SecurityToken securityToken = tokenSecurityEvent.getSecurityToken();
            if (securityToken.getKeyWrappingToken() != null) {
                while (securityToken.getKeyWrappingToken() != null) {
                    securityToken = securityToken.getKeyWrappingToken();
                }
                if (!containsSecurityToken(supportingTokens, securityToken)) {
                    TokenSecurityEvent newTokenSecurityEvent = WSSUtils.createTokenSecurityEvent(securityToken);
                    supportingTokens = addTokenSecurityEvent(newTokenSecurityEvent, supportingTokens);
                    securityEventDeque.offer(newTokenSecurityEvent);
                }
                //remove old TokenSecurityEvent so that only root tokens are in the queue
                securityEventDeque.remove(tokenSecurityEvent);
            }
        }

        Iterator<TokenSecurityEvent> supportingTokensIterator = supportingTokens.iterator();
        while (supportingTokensIterator.hasNext()) {
            TokenSecurityEvent tokenSecurityEvent = supportingTokensIterator.next();
            List<SecurityToken> signingSecurityTokens = isSignedToken(tokenSecurityEvent, securityEventDeque, httpsTokenSecurityEvent);

            List<QName> signatureElementPath = new ArrayList<QName>(4);
            signatureElementPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
            signatureElementPath.add(WSSConstants.TAG_dsig_Signature);
            boolean signsSignature = signsElement(tokenSecurityEvent, signatureElementPath, securityEventDeque);
            boolean encryptsSignature = encryptsElement(tokenSecurityEvent, signatureElementPath, securityEventDeque);

            List<QName> signatureConfirmationElementPath = new ArrayList<QName>(4);
            signatureConfirmationElementPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
            signatureConfirmationElementPath.add(WSSConstants.TAG_wsse11_SignatureConfirmation);
            boolean signsSignatureConfirmation = signsElement(tokenSecurityEvent, signatureConfirmationElementPath, securityEventDeque);
            boolean encryptsSignatureConfirmation = encryptsElement(tokenSecurityEvent, signatureConfirmationElementPath, securityEventDeque);

            List<QName> timestampElementPath = new ArrayList<QName>(4);
            timestampElementPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
            timestampElementPath.add(WSSConstants.TAG_wsu_Timestamp);
            boolean signsTimestamp = signsElement(tokenSecurityEvent, timestampElementPath, securityEventDeque);

            List<QName> usernameTokenElementPath = new ArrayList<QName>(4);
            timestampElementPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
            timestampElementPath.add(WSSConstants.TAG_wsse_UsernameToken);
            boolean encryptsUsernameToken = encryptsElement(tokenSecurityEvent, usernameTokenElementPath, securityEventDeque);

            boolean transportSecurityActive = Boolean.TRUE == get(WSSConstants.TRANSPORT_SECURITY_ACTIVE);

            List<SecurityToken> encryptingSecurityTokens = isEncryptedToken(tokenSecurityEvent, securityEventDeque);

            boolean signatureUsage = tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(SecurityToken.TokenUsage.Signature);
            boolean encryptionUsage = tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(SecurityToken.TokenUsage.Encryption);

            if (!transportSecurityActive && signsSignatureConfirmation && signsTimestamp && !signsSignature) {
                supportingTokensIterator.remove();
                messageSignatureTokens = addTokenSecurityEvent(tokenSecurityEvent, messageSignatureTokens);
                if (encryptionUsage) {
                    messageEncryptionTokens = addTokenSecurityEvent(tokenSecurityEvent, messageEncryptionTokens);
                }
            } else if (!transportSecurityActive && signsSignatureConfirmation && !signsSignature) {
                supportingTokensIterator.remove();
                messageSignatureTokens = addTokenSecurityEvent(tokenSecurityEvent, messageSignatureTokens);
                if (encryptionUsage) {
                    messageEncryptionTokens = addTokenSecurityEvent(tokenSecurityEvent, messageEncryptionTokens);
                }
            } else if (!transportSecurityActive && signsTimestamp && !signsSignature) {
                supportingTokensIterator.remove();
                messageSignatureTokens = addTokenSecurityEvent(tokenSecurityEvent, messageSignatureTokens);
                if (encryptionUsage) {
                    messageEncryptionTokens = addTokenSecurityEvent(tokenSecurityEvent, messageEncryptionTokens);
                }
            } else if (!transportSecurityActive &&
                    (encryptsSignature || encryptsSignatureConfirmation || encryptsUsernameToken)) {
                supportingTokensIterator.remove();
                messageEncryptionTokens = addTokenSecurityEvent(tokenSecurityEvent, messageEncryptionTokens);
            } else if (signsSignature && signingSecurityTokens.size() > 0 && encryptingSecurityTokens.size() > 0) {
                supportingTokensIterator.remove();
                signedEndorsingEncryptedSupportingTokens = addTokenSecurityEvent(tokenSecurityEvent, signedEndorsingEncryptedSupportingTokens);
            } else if (signsSignature && signingSecurityTokens.size() == 0 && encryptingSecurityTokens.size() > 0) {
                supportingTokensIterator.remove();
                endorsingEncryptedSupportingTokens = addTokenSecurityEvent(tokenSecurityEvent, endorsingEncryptedSupportingTokens);
            } else if (signsSignature && signingSecurityTokens.size() > 0) {
                supportingTokensIterator.remove();
                signedEndorsingSupportingTokens = addTokenSecurityEvent(tokenSecurityEvent, signedEndorsingSupportingTokens);
            } else if (signatureUsage && signingSecurityTokens.size() > 0) {
                supportingTokensIterator.remove();
                signedEndorsingSupportingTokens = addTokenSecurityEvent(tokenSecurityEvent, signedEndorsingSupportingTokens);
            } else if (signsSignature) {
                supportingTokensIterator.remove();
                endorsingSupportingTokens = addTokenSecurityEvent(tokenSecurityEvent, endorsingSupportingTokens);
            } else if (signingSecurityTokens.size() > 0 && encryptingSecurityTokens.size() > 0) {
                supportingTokensIterator.remove();
                signedEncryptedSupportingTokens = addTokenSecurityEvent(tokenSecurityEvent, signedEncryptedSupportingTokens);
            } else if (signingSecurityTokens.size() > 0) {
                supportingTokensIterator.remove();
                signedSupportingTokens = addTokenSecurityEvent(tokenSecurityEvent, signedSupportingTokens);
            } else if (encryptingSecurityTokens.size() > 0) {
                supportingTokensIterator.remove();
                encryptedSupportingTokens = addTokenSecurityEvent(tokenSecurityEvent, encryptedSupportingTokens);
            }
        }

        if (messageSignatureTokens.isEmpty()) {
            SecurityToken messageSignatureToken = getSupportingTokenSigningToken(
                    signedSupportingTokens,
                    signedEndorsingSupportingTokens,
                    signedEncryptedSupportingTokens,
                    signedEndorsingEncryptedSupportingTokens,
                    securityEventDeque);

            TokenSecurityEvent tokenSecurityEvent = getTokenSecurityEvent(messageSignatureToken, tokenSecurityEvents);
            if (tokenSecurityEvent != null) {
                supportingTokens.remove(tokenSecurityEvent);
                signedSupportingTokens.remove(tokenSecurityEvent);
                endorsingSupportingTokens.remove(tokenSecurityEvent);
                signedEndorsingSupportingTokens.remove(tokenSecurityEvent);
                signedEncryptedSupportingTokens.remove(tokenSecurityEvent);
                encryptedSupportingTokens.remove(tokenSecurityEvent);
                endorsingEncryptedSupportingTokens.remove(tokenSecurityEvent);
                signedEndorsingEncryptedSupportingTokens.remove(tokenSecurityEvent);
                messageSignatureTokens = addTokenSecurityEvent(tokenSecurityEvent, messageSignatureTokens);
            }
        }

        if (messageSignatureTokens.isEmpty()) {
            for (Iterator<TokenSecurityEvent> iterator = supportingTokens.iterator(); iterator.hasNext(); ) {
                TokenSecurityEvent supportingToken = iterator.next();
                if (supportingToken.getSecurityToken().getTokenUsages().contains(SecurityToken.TokenUsage.Signature)) {
                    iterator.remove();
                    messageSignatureTokens = addTokenSecurityEvent(supportingToken, messageSignatureTokens);
                    break;
                }
            }
        }

        if (messageEncryptionTokens.isEmpty()) {
            for (Iterator<TokenSecurityEvent> iterator = supportingTokens.iterator(); iterator.hasNext(); ) {
                TokenSecurityEvent supportingToken = iterator.next();
                if (supportingToken.getSecurityToken().getTokenUsages().contains(SecurityToken.TokenUsage.Encryption)) {
                    iterator.remove();
                    messageEncryptionTokens = addTokenSecurityEvent(supportingToken, messageEncryptionTokens);
                    break;
                }
            }
        }

        if (!messageEncryptionTokens.isEmpty()) {
            this.messageEncryptionTokenOccured = true;
        }

        setTokenUsage(messageSignatureTokens, SecurityToken.TokenUsage.MainSignature);
        setTokenUsage(messageEncryptionTokens, SecurityToken.TokenUsage.MainEncryption);
        setTokenUsage(supportingTokens, SecurityToken.TokenUsage.SupportingTokens);
        setTokenUsage(signedSupportingTokens, SecurityToken.TokenUsage.SignedSupportingTokens);
        setTokenUsage(endorsingSupportingTokens, SecurityToken.TokenUsage.EndorsingSupportingTokens);
        setTokenUsage(signedEndorsingSupportingTokens, SecurityToken.TokenUsage.SignedEndorsingSupportingTokens);
        setTokenUsage(signedEncryptedSupportingTokens, SecurityToken.TokenUsage.SignedEncryptedSupportingTokens);
        setTokenUsage(encryptedSupportingTokens, SecurityToken.TokenUsage.EncryptedSupportingTokens);
        setTokenUsage(endorsingEncryptedSupportingTokens, SecurityToken.TokenUsage.EndorsingEncryptedSupportingTokens);
        setTokenUsage(signedEndorsingEncryptedSupportingTokens, SecurityToken.TokenUsage.SignedEndorsingEncryptedSupportingTokens);
    }

    private List<TokenSecurityEvent> addTokenSecurityEvent(TokenSecurityEvent tokenSecurityEvent, List<TokenSecurityEvent> tokenSecurityEventList) {
        if (tokenSecurityEventList == Collections.<TokenSecurityEvent>emptyList()) {
            tokenSecurityEventList = new ArrayList<TokenSecurityEvent>();
        }
        tokenSecurityEventList.add(tokenSecurityEvent);
        return tokenSecurityEventList;
    }

    private boolean containsSecurityToken(List<TokenSecurityEvent> supportingTokens, SecurityToken securityToken) {
        for (int i = 0; i < supportingTokens.size(); i++) {
            TokenSecurityEvent tokenSecurityEvent = supportingTokens.get(i);
            if (tokenSecurityEvent.getSecurityToken() == securityToken) {
                return true;
            }
        }
        return false;
    }

    private TokenSecurityEvent getTokenSecurityEvent(SecurityToken securityToken, List<TokenSecurityEvent> tokenSecurityEvents) throws XMLSecurityException {
        for (int i = 0; i < tokenSecurityEvents.size(); i++) {
            TokenSecurityEvent tokenSecurityEvent = tokenSecurityEvents.get(i);
            if (tokenSecurityEvent.getSecurityToken() == securityToken) {
                return tokenSecurityEvent;
            }
        }
        return null;
    }

    private SecurityToken getSupportingTokenSigningToken(
            List<TokenSecurityEvent> signedSupportingTokens,
            List<TokenSecurityEvent> signedEndorsingSupportingTokens,
            List<TokenSecurityEvent> signedEncryptedSupportingTokens,
            List<TokenSecurityEvent> signedEndorsingEncryptedSupportingTokens,
            Deque<SecurityEvent> securityEventDeque
    ) throws XMLSecurityException {

        //todo we have to check if the signingTokens also cover the other supporting tokens!
        for (int i = 0; i < signedSupportingTokens.size(); i++) {
            TokenSecurityEvent tokenSecurityEvent = signedSupportingTokens.get(i);
            List<SecurityToken> signingSecurityTokens = getSigningToken(tokenSecurityEvent, securityEventDeque);
            if (signingSecurityTokens.size() == 1) {
                return signingSecurityTokens.get(0);
            }
        }
        for (int i = 0; i < signedEndorsingSupportingTokens.size(); i++) {
            TokenSecurityEvent tokenSecurityEvent = signedEndorsingSupportingTokens.get(i);
            List<SecurityToken> signingSecurityTokens = getSigningToken(tokenSecurityEvent, securityEventDeque);
            if (signingSecurityTokens.size() == 1) {
                return signingSecurityTokens.get(0);
            }
        }
        for (int i = 0; i < signedEncryptedSupportingTokens.size(); i++) {
            TokenSecurityEvent tokenSecurityEvent = signedEncryptedSupportingTokens.get(i);
            List<SecurityToken> signingSecurityTokens = getSigningToken(tokenSecurityEvent, securityEventDeque);
            if (signingSecurityTokens.size() == 1) {
                return signingSecurityTokens.get(0);
            }
        }
        for (int i = 0; i < signedEndorsingEncryptedSupportingTokens.size(); i++) {
            TokenSecurityEvent tokenSecurityEvent = signedEndorsingEncryptedSupportingTokens.get(i);
            List<SecurityToken> signingSecurityTokens = getSigningToken(tokenSecurityEvent, securityEventDeque);
            if (signingSecurityTokens.size() == 1) {
                return signingSecurityTokens.get(0);
            }
        }
        return null;
    }

    private List<SecurityToken> getSigningToken(TokenSecurityEvent tokenSecurityEvent, Deque<SecurityEvent> securityEventDeque) throws XMLSecurityException {
        List<SecurityToken> signingSecurityTokens = new ArrayList<SecurityToken>();

        for (Iterator<SecurityEvent> iterator = securityEventDeque.iterator(); iterator.hasNext(); ) {
            SecurityEvent securityEvent = iterator.next();
            if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.SignedElement) {
                SignedElementSecurityEvent signedElementSecurityEvent = (SignedElementSecurityEvent) securityEvent;
                if (signedElementSecurityEvent.isSigned()
                        && WSSUtils.pathMatches(signedElementSecurityEvent.getElementPath(), tokenSecurityEvent.getSecurityToken().getElementPath(), true, false)) {
                    signingSecurityTokens.add(signedElementSecurityEvent.getSecurityToken());
                }
            }
        }
        return signingSecurityTokens;
    }

    private void setTokenUsage(List<TokenSecurityEvent> tokenSecurityEvents, SecurityToken.TokenUsage tokenUsage) throws XMLSecurityException {
        for (int i = 0; i < tokenSecurityEvents.size(); i++) {
            TokenSecurityEvent tokenSecurityEvent = tokenSecurityEvents.get(i);
            setTokenUsage(tokenSecurityEvent, tokenUsage);
        }
    }

    private void setTokenUsage(TokenSecurityEvent tokenSecurityEvent, SecurityToken.TokenUsage tokenUsage) throws XMLSecurityException {
        //if (tokenUsage == SecurityToken.TokenUsage.MainSignature) {
        tokenSecurityEvent.getSecurityToken().getTokenUsages().remove(SecurityToken.TokenUsage.SupportingTokens);
        //} else if (tokenUsage == SecurityToken.TokenUsage.MainEncryption) {
        tokenSecurityEvent.getSecurityToken().getTokenUsages().remove(SecurityToken.TokenUsage.SupportingTokens);
        //}
        tokenSecurityEvent.getSecurityToken().getTokenUsages().remove(SecurityToken.TokenUsage.Signature);
        tokenSecurityEvent.getSecurityToken().getTokenUsages().remove(SecurityToken.TokenUsage.Encryption);
        tokenSecurityEvent.getSecurityToken().addTokenUsage(tokenUsage);
    }

    private List<SecurityToken> isSignedToken(TokenSecurityEvent tokenSecurityEvent,
                                              Deque<SecurityEvent> securityEventDeque,
                                              HttpsTokenSecurityEvent httpsTokenSecurityEvent) throws XMLSecurityException {
        List<SecurityToken> securityTokenList = new ArrayList<SecurityToken>();
        if (httpsTokenSecurityEvent != null) {
            securityTokenList.add(httpsTokenSecurityEvent.getSecurityToken());
            return securityTokenList;
        }
        for (Iterator<SecurityEvent> iterator = securityEventDeque.iterator(); iterator.hasNext(); ) {
            SecurityEvent securityEvent = iterator.next();
            if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.SignedElement) {
                SignedElementSecurityEvent signedElementSecurityEvent = (SignedElementSecurityEvent) securityEvent;
                if (signedElementSecurityEvent.isSigned()
                        && tokenSecurityEvent.getSecurityToken() != null
                        && signedElementSecurityEvent.getXmlSecEvent() != null
                        && signedElementSecurityEvent.getXmlSecEvent() == tokenSecurityEvent.getSecurityToken().getXMLSecEvent()
                    /*&& WSSUtils.pathMatches(
                  tokenSecurityEvent.getSecurityToken().getElementPath(),
                  signedElementSecurityEvent.getElementPath(), false, false)*/) {

                    if (!securityTokenList.contains(signedElementSecurityEvent.getSecurityToken())) {
                        securityTokenList.add(signedElementSecurityEvent.getSecurityToken());
                    }
                }
            }
        }
        return securityTokenList;
    }

    private List<SecurityToken> isEncryptedToken(TokenSecurityEvent tokenSecurityEvent,
                                                 Deque<SecurityEvent> securityEventDeque) throws XMLSecurityException {

        List<SecurityToken> securityTokenList = new ArrayList<SecurityToken>();
        for (Iterator<SecurityEvent> iterator = securityEventDeque.iterator(); iterator.hasNext(); ) {
            SecurityEvent securityEvent = iterator.next();
            if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.EncryptedElement) {
                EncryptedElementSecurityEvent encryptedElementSecurityEvent = (EncryptedElementSecurityEvent) securityEvent;
                if (encryptedElementSecurityEvent.isEncrypted()
                        && tokenSecurityEvent.getSecurityToken() != null
                        && encryptedElementSecurityEvent.getXmlSecEvent() != null
                        && encryptedElementSecurityEvent.getXmlSecEvent() == tokenSecurityEvent.getSecurityToken().getXMLSecEvent()) {

                    if (!securityTokenList.contains(encryptedElementSecurityEvent.getSecurityToken())) {
                        securityTokenList.add(encryptedElementSecurityEvent.getSecurityToken());
                    }
                }
            }
        }
        return securityTokenList;
    }

    private boolean signsElement(TokenSecurityEvent tokenSecurityEvent, List<QName> elementPath,
                                 Deque<SecurityEvent> securityEventDeque) throws XMLSecurityException {
        for (Iterator<SecurityEvent> iterator = securityEventDeque.iterator(); iterator.hasNext(); ) {
            SecurityEvent securityEvent = iterator.next();
            if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.SignedElement) {
                SignedElementSecurityEvent signedElementSecurityEvent = (SignedElementSecurityEvent) securityEvent;
                if (signedElementSecurityEvent.isSigned()
                        && signedElementSecurityEvent.getSecurityToken() == tokenSecurityEvent.getSecurityToken()
                        && WSSUtils.pathMatches(elementPath, signedElementSecurityEvent.getElementPath(), true, false)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean encryptsElement(TokenSecurityEvent tokenSecurityEvent, List<QName> elementPath,
                                    Deque<SecurityEvent> securityEventDeque) throws XMLSecurityException {
        for (Iterator<SecurityEvent> iterator = securityEventDeque.iterator(); iterator.hasNext(); ) {
            SecurityEvent securityEvent = iterator.next();
            if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.EncryptedElement) {
                EncryptedElementSecurityEvent encryptedElementSecurityEvent = (EncryptedElementSecurityEvent) securityEvent;
                if (encryptedElementSecurityEvent.isEncrypted()
                        && encryptedElementSecurityEvent.getSecurityToken() == tokenSecurityEvent.getSecurityToken()
                        && WSSUtils.pathMatches(elementPath, encryptedElementSecurityEvent.getElementPath(), true, false)) {
                    return true;
                }
            } else if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.ContentEncrypted) {
                ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent = (ContentEncryptedElementSecurityEvent) securityEvent;
                if (contentEncryptedElementSecurityEvent.isEncrypted()
                        && contentEncryptedElementSecurityEvent.getSecurityToken() == tokenSecurityEvent.getSecurityToken()
                        && contentEncryptedElementSecurityEvent.getXmlSecEvent() == tokenSecurityEvent.getSecurityToken().getXMLSecEvent()
                        && WSSUtils.pathMatches(elementPath, contentEncryptedElementSecurityEvent.getElementPath(), true, false)) {
                    return true;
                }
            }
        }
        return false;
    }

    public void handleBSPRule(WSSConstants.BSPRule bspRule) throws WSSecurityException {
        if (!ignoredBSPRules.contains(bspRule)) {
            throw new WSSecurityException("BSP:" + bspRule.name() + ": " + bspRule.getMsg());
        } else {
            logger.warn("BSP:" + bspRule.name() + ": " + bspRule.getMsg());
        }
    }

    public void ignoredBSPRules(List<WSSConstants.BSPRule> bspRules) {
        ignoredBSPRules = new ArrayList<WSSConstants.BSPRule>(bspRules);
    }
}
