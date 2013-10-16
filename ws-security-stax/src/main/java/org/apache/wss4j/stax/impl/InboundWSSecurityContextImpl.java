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
package org.apache.wss4j.stax.impl;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSUtils;
import org.apache.wss4j.stax.securityEvent.HttpsTokenSecurityEvent;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.impl.InboundSecurityContextImpl;
import org.apache.xml.security.stax.securityEvent.AlgorithmSuiteSecurityEvent;
import org.apache.xml.security.stax.securityEvent.ContentEncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.EncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.SignedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityToken;

/**
 * Concrete security context implementation
 */
public class InboundWSSecurityContextImpl extends InboundSecurityContextImpl implements WSInboundSecurityContext {

    private static final transient org.slf4j.Logger logger =
            org.slf4j.LoggerFactory.getLogger(InboundWSSecurityContextImpl.class);

    private final Deque<SecurityEvent> securityEventQueue = new ArrayDeque<SecurityEvent>();
    private boolean operationSecurityEventOccured = false;
    private boolean messageEncryptionTokenOccured = false;
    private boolean allowRSA15KeyTransportAlgorithm = false;
    private boolean disableBSPEnforcement;

    private List<BSPRule> ignoredBSPRules = Collections.emptyList();

    @Override
    public synchronized void registerSecurityEvent(SecurityEvent securityEvent) throws XMLSecurityException {

        if (WSSecurityEventConstants.AlgorithmSuite.equals(securityEvent.getSecurityEventType())) {
            //do not cache AlgorithmSuite securityEvents and forward them directly to allow
            //the user to check them before they are used internally.
            forwardSecurityEvent(securityEvent);
            return;
        }

        if (operationSecurityEventOccured) {
            if (!this.messageEncryptionTokenOccured
                    && securityEvent instanceof TokenSecurityEvent) {
                @SuppressWarnings("unchecked")
                TokenSecurityEvent<? extends InboundSecurityToken> tokenSecurityEvent =
                        ((TokenSecurityEvent<? extends InboundSecurityToken>) securityEvent);

                if (tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_Encryption)) {
                    InboundSecurityToken securityToken = WSSUtils.getRootToken(tokenSecurityEvent.getSecurityToken());

                    TokenSecurityEvent<? extends InboundSecurityToken> newTokenSecurityEvent =
                            WSSUtils.createTokenSecurityEvent(securityToken, tokenSecurityEvent.getCorrelationID());
                    setTokenUsage(newTokenSecurityEvent, WSSecurityTokenConstants.TokenUsage_MainEncryption);
                    securityEvent = newTokenSecurityEvent;
                    this.messageEncryptionTokenOccured = true;
                }
            }

            forwardSecurityEvent(securityEvent);
            return;
        }

        if (WSSecurityEventConstants.Operation.equals(securityEvent.getSecurityEventType())) {
            operationSecurityEventOccured = true;

            identifySecurityTokenDepenedenciesAndUsage(securityEventQueue);

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

    @Override
    protected void forwardSecurityEvent(SecurityEvent securityEvent) throws XMLSecurityException {

        if (!allowRSA15KeyTransportAlgorithm && SecurityEventConstants.AlgorithmSuite.equals(securityEvent.getSecurityEventType())) {
            AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = (AlgorithmSuiteSecurityEvent)securityEvent;
            Boolean allowRSA15 = get(WSSConstants.PROP_ALLOW_RSA15_KEYTRANSPORT_ALGORITHM);
            if ((allowRSA15 == null || !allowRSA15) && WSSConstants.NS_XENC_RSA15.equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, WSSConstants.PROP_ALLOW_RSA15_KEYTRANSPORT_ALGORITHM);
            }
        }

        try {
            super.forwardSecurityEvent(securityEvent);
        } catch (WSSecurityException e) {
            throw e;
        } catch (XMLSecurityException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
        }
    }

    private void identifySecurityTokenDepenedenciesAndUsage(
            Deque<SecurityEvent> securityEventDeque) throws XMLSecurityException {

        List<TokenSecurityEvent<? extends InboundSecurityToken>> messageSignatureTokens = Collections.emptyList();
        List<TokenSecurityEvent<? extends InboundSecurityToken>> messageEncryptionTokens = Collections.emptyList();
        List<TokenSecurityEvent<? extends InboundSecurityToken>> supportingTokens = Collections.emptyList();
        List<TokenSecurityEvent<? extends InboundSecurityToken>> signedSupportingTokens = Collections.emptyList();
        List<TokenSecurityEvent<? extends InboundSecurityToken>> endorsingSupportingTokens = Collections.emptyList();
        List<TokenSecurityEvent<? extends InboundSecurityToken>> signedEndorsingSupportingTokens = Collections.emptyList();
        List<TokenSecurityEvent<? extends InboundSecurityToken>> signedEncryptedSupportingTokens = Collections.emptyList();
        List<TokenSecurityEvent<? extends InboundSecurityToken>> encryptedSupportingTokens = Collections.emptyList();
        List<TokenSecurityEvent<? extends InboundSecurityToken>> endorsingEncryptedSupportingTokens = Collections.emptyList();
        List<TokenSecurityEvent<? extends InboundSecurityToken>> signedEndorsingEncryptedSupportingTokens = Collections.emptyList();

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = null;

        List<TokenSecurityEvent<? extends InboundSecurityToken>> tokenSecurityEvents =
                new ArrayList<TokenSecurityEvent<? extends InboundSecurityToken>>();
        Iterator<SecurityEvent> securityEventIterator = securityEventDeque.iterator();
        while (securityEventIterator.hasNext()) {
            SecurityEvent securityEvent = securityEventIterator.next();
            if (securityEvent instanceof TokenSecurityEvent) {
                @SuppressWarnings("unchecked")
                TokenSecurityEvent<? extends InboundSecurityToken> tokenSecurityEvent =
                        (TokenSecurityEvent<? extends InboundSecurityToken>)securityEvent;

                if (WSSecurityEventConstants.HttpsToken.equals(securityEvent.getSecurityEventType())) {
                    HttpsTokenSecurityEvent actHttpsTokenSecurityEvent = (HttpsTokenSecurityEvent) tokenSecurityEvent;
                    actHttpsTokenSecurityEvent.getSecurityToken().getTokenUsages().clear();
                    actHttpsTokenSecurityEvent.getSecurityToken().addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
                    messageSignatureTokens = addTokenSecurityEvent(actHttpsTokenSecurityEvent, messageSignatureTokens);
                    HttpsTokenSecurityEvent clonedHttpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
                    clonedHttpsTokenSecurityEvent.setAuthenticationType(actHttpsTokenSecurityEvent.getAuthenticationType());
                    clonedHttpsTokenSecurityEvent.setIssuerName(actHttpsTokenSecurityEvent.getIssuerName());
                    clonedHttpsTokenSecurityEvent.setSecurityToken(actHttpsTokenSecurityEvent.getSecurityToken());
                    clonedHttpsTokenSecurityEvent.getSecurityToken().addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainEncryption);
                    messageEncryptionTokens = addTokenSecurityEvent(actHttpsTokenSecurityEvent, messageEncryptionTokens);
                    httpsTokenSecurityEvent = clonedHttpsTokenSecurityEvent;
                    continue;
                }
                tokenSecurityEvents.add(tokenSecurityEvent);
            }
        }

        //search the root tokens and create new TokenSecurityEvents if not already there...
        for (int i = 0; i < tokenSecurityEvents.size(); i++) {
            TokenSecurityEvent<? extends InboundSecurityToken> tokenSecurityEvent = tokenSecurityEvents.get(i);
            InboundSecurityToken securityToken = WSSUtils.getRootToken(tokenSecurityEvent.getSecurityToken());

            if (!containsSecurityToken(supportingTokens, securityToken)) {
                TokenSecurityEvent<? extends InboundSecurityToken> newTokenSecurityEvent =
                        WSSUtils.createTokenSecurityEvent(securityToken, tokenSecurityEvent.getCorrelationID());
                supportingTokens = addTokenSecurityEvent(newTokenSecurityEvent, supportingTokens);
                securityEventDeque.offer(newTokenSecurityEvent);
            }
            //remove old TokenSecurityEvent so that only root tokens are in the queue
            securityEventDeque.remove(tokenSecurityEvent);
        }

        Iterator<TokenSecurityEvent<? extends InboundSecurityToken>> supportingTokensIterator = supportingTokens.iterator();
        while (supportingTokensIterator.hasNext()) {
            TokenSecurityEvent<? extends InboundSecurityToken> tokenSecurityEvent = supportingTokensIterator.next();
            List<InboundSecurityToken> signingSecurityTokens = isSignedToken(tokenSecurityEvent, securityEventDeque, httpsTokenSecurityEvent);

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
            usernameTokenElementPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
            usernameTokenElementPath.add(WSSConstants.TAG_wsse_UsernameToken);
            boolean encryptsUsernameToken = encryptsElement(tokenSecurityEvent, usernameTokenElementPath, securityEventDeque);

            boolean transportSecurityActive = Boolean.TRUE == get(WSSConstants.TRANSPORT_SECURITY_ACTIVE);

            List<InboundSecurityToken> encryptingSecurityTokens = isEncryptedToken(tokenSecurityEvent, securityEventDeque, httpsTokenSecurityEvent);

            boolean signatureUsage = tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_Signature);
            boolean encryptionUsage = tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_Encryption);

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
            } else if (transportSecurityActive && signsTimestamp && signingSecurityTokens.size() > 0 && encryptingSecurityTokens.size() > 0) {
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
            InboundSecurityToken messageSignatureToken = getSupportingTokenSigningToken(
                    signedSupportingTokens,
                    signedEndorsingSupportingTokens,
                    signedEncryptedSupportingTokens,
                    signedEndorsingEncryptedSupportingTokens,
                    securityEventDeque);

            TokenSecurityEvent<? extends InboundSecurityToken> tokenSecurityEvent =
                    getTokenSecurityEvent(messageSignatureToken, tokenSecurityEvents);
            if (tokenSecurityEvent != null) {
                removeTokenSecurityEvent(tokenSecurityEvent, supportingTokens);
                removeTokenSecurityEvent(tokenSecurityEvent, signedSupportingTokens);
                removeTokenSecurityEvent(tokenSecurityEvent, endorsingSupportingTokens);
                removeTokenSecurityEvent(tokenSecurityEvent, signedEndorsingSupportingTokens);
                removeTokenSecurityEvent(tokenSecurityEvent, signedEncryptedSupportingTokens);
                removeTokenSecurityEvent(tokenSecurityEvent, encryptedSupportingTokens);
                removeTokenSecurityEvent(tokenSecurityEvent, endorsingEncryptedSupportingTokens);
                removeTokenSecurityEvent(tokenSecurityEvent, signedEndorsingEncryptedSupportingTokens);
                messageSignatureTokens = addTokenSecurityEvent(tokenSecurityEvent, messageSignatureTokens);
            }
        }

        if (messageSignatureTokens.isEmpty()) {
            for (Iterator<TokenSecurityEvent<? extends InboundSecurityToken>> iterator = supportingTokens.iterator(); iterator.hasNext(); ) {
                TokenSecurityEvent<? extends InboundSecurityToken> supportingToken = iterator.next();
                if (supportingToken.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_Signature)) {
                    iterator.remove();
                    messageSignatureTokens = addTokenSecurityEvent(supportingToken, messageSignatureTokens);
                    break;
                }
            }
        }

        if (messageEncryptionTokens.isEmpty()) {
            for (Iterator<TokenSecurityEvent<? extends InboundSecurityToken>> iterator = supportingTokens.iterator(); iterator.hasNext(); ) {
                TokenSecurityEvent<? extends InboundSecurityToken> supportingToken = iterator.next();
                if (supportingToken.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_Encryption)) {
                    iterator.remove();
                    messageEncryptionTokens = addTokenSecurityEvent(supportingToken, messageEncryptionTokens);
                    break;
                }
            }
        }

        if (!messageEncryptionTokens.isEmpty()) {
            this.messageEncryptionTokenOccured = true;
        }

        setTokenUsage(messageSignatureTokens, WSSecurityTokenConstants.TokenUsage_MainSignature);
        setTokenUsage(messageEncryptionTokens, WSSecurityTokenConstants.TokenUsage_MainEncryption);
        setTokenUsage(supportingTokens, WSSecurityTokenConstants.TokenUsage_SupportingTokens);
        setTokenUsage(signedSupportingTokens, WSSecurityTokenConstants.TokenUsage_SignedSupportingTokens);
        setTokenUsage(endorsingSupportingTokens, WSSecurityTokenConstants.TokenUsage_EndorsingSupportingTokens);
        setTokenUsage(signedEndorsingSupportingTokens, WSSecurityTokenConstants.TokenUsage_SignedEndorsingSupportingTokens);
        setTokenUsage(signedEncryptedSupportingTokens, WSSecurityTokenConstants.TokenUsage_SignedEncryptedSupportingTokens);
        setTokenUsage(encryptedSupportingTokens, WSSecurityTokenConstants.TokenUsage_EncryptedSupportingTokens);
        setTokenUsage(endorsingEncryptedSupportingTokens, WSSecurityTokenConstants.TokenUsage_EndorsingEncryptedSupportingTokens);
        setTokenUsage(signedEndorsingEncryptedSupportingTokens, WSSecurityTokenConstants.TokenUsage_SignedEndorsingEncryptedSupportingTokens);
    }

    private void removeTokenSecurityEvent(TokenSecurityEvent<? extends InboundSecurityToken> tokenSecurityEvent,
                                          List<TokenSecurityEvent<? extends InboundSecurityToken>> tokenSecurityEventList) {
        for (int i = 0; i < tokenSecurityEventList.size(); i++) {
            TokenSecurityEvent<? extends InboundSecurityToken> securityEvent = tokenSecurityEventList.get(i);
            if (securityEvent.getSecurityToken().getId().equals(tokenSecurityEvent.getSecurityToken().getId())) {
                tokenSecurityEventList.remove(securityEvent);
                return;
            }
        }
    }

    private List<TokenSecurityEvent<? extends InboundSecurityToken>> addTokenSecurityEvent(
            TokenSecurityEvent<? extends InboundSecurityToken> tokenSecurityEvent,
            List<TokenSecurityEvent<? extends InboundSecurityToken>> tokenSecurityEventList) {
        if (tokenSecurityEventList == Collections.<TokenSecurityEvent<? extends InboundSecurityToken>>emptyList()) {
            tokenSecurityEventList = new ArrayList<TokenSecurityEvent<? extends InboundSecurityToken>>();
        }
        tokenSecurityEventList.add(tokenSecurityEvent);
        return tokenSecurityEventList;
    }

    private boolean containsSecurityToken(List<TokenSecurityEvent<? extends InboundSecurityToken>> supportingTokens, SecurityToken securityToken) {
        if (securityToken != null) {
            for (int i = 0; i < supportingTokens.size(); i++) {
                TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent = supportingTokens.get(i);
                if (tokenSecurityEvent.getSecurityToken().getId().equals(securityToken.getId())) {
                    return true;
                }
            }
        }
        return false;
    }

    private TokenSecurityEvent<? extends InboundSecurityToken> getTokenSecurityEvent(
            InboundSecurityToken securityToken,
            List<TokenSecurityEvent<? extends InboundSecurityToken>> tokenSecurityEvents) throws XMLSecurityException {
        if (securityToken != null) {
            for (int i = 0; i < tokenSecurityEvents.size(); i++) {
                TokenSecurityEvent<? extends InboundSecurityToken> tokenSecurityEvent = tokenSecurityEvents.get(i);
                if (tokenSecurityEvent.getSecurityToken().getId().equals(securityToken.getId())) {
                    return tokenSecurityEvent;
                }
            }
        }
        return null;
    }

    private InboundSecurityToken getSupportingTokenSigningToken(
            List<TokenSecurityEvent<? extends InboundSecurityToken>> signedSupportingTokens,
            List<TokenSecurityEvent<? extends InboundSecurityToken>> signedEndorsingSupportingTokens,
            List<TokenSecurityEvent<? extends InboundSecurityToken>> signedEncryptedSupportingTokens,
            List<TokenSecurityEvent<? extends InboundSecurityToken>> signedEndorsingEncryptedSupportingTokens,
            Deque<SecurityEvent> securityEventDeque
    ) throws XMLSecurityException {

        //todo we have to check if the signingTokens also cover the other supporting tokens!
        for (int i = 0; i < signedSupportingTokens.size(); i++) {
            TokenSecurityEvent<? extends InboundSecurityToken> tokenSecurityEvent = signedSupportingTokens.get(i);
            List<? extends InboundSecurityToken> signingSecurityTokens = getSigningToken(tokenSecurityEvent, securityEventDeque);
            if (signingSecurityTokens.size() == 1) {
                return signingSecurityTokens.get(0);
            }
        }
        for (int i = 0; i < signedEndorsingSupportingTokens.size(); i++) {
            TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent = signedEndorsingSupportingTokens.get(i);
            List<InboundSecurityToken> signingSecurityTokens = getSigningToken(tokenSecurityEvent, securityEventDeque);
            if (signingSecurityTokens.size() == 1) {
                return signingSecurityTokens.get(0);
            }
        }
        for (int i = 0; i < signedEncryptedSupportingTokens.size(); i++) {
            TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent = signedEncryptedSupportingTokens.get(i);
            List<InboundSecurityToken> signingSecurityTokens = getSigningToken(tokenSecurityEvent, securityEventDeque);
            if (signingSecurityTokens.size() == 1) {
                return signingSecurityTokens.get(0);
            }
        }
        for (int i = 0; i < signedEndorsingEncryptedSupportingTokens.size(); i++) {
            TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent = signedEndorsingEncryptedSupportingTokens.get(i);
            List<InboundSecurityToken> signingSecurityTokens = getSigningToken(tokenSecurityEvent, securityEventDeque);
            if (signingSecurityTokens.size() == 1) {
                return signingSecurityTokens.get(0);
            }
        }
        return null;
    }

    private List<InboundSecurityToken> getSigningToken(TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent, Deque<SecurityEvent> securityEventDeque) throws XMLSecurityException {
        List<InboundSecurityToken> signingSecurityTokens = new ArrayList<InboundSecurityToken>();

        for (Iterator<SecurityEvent> iterator = securityEventDeque.iterator(); iterator.hasNext(); ) {
            SecurityEvent securityEvent = iterator.next();
            if (WSSecurityEventConstants.SignedElement.equals(securityEvent.getSecurityEventType())) {
                SignedElementSecurityEvent signedElementSecurityEvent = (SignedElementSecurityEvent) securityEvent;
                if (signedElementSecurityEvent.isSigned()
                        && WSSUtils.pathMatches(
                        signedElementSecurityEvent.getElementPath(),
                        ((InboundSecurityToken)tokenSecurityEvent.getSecurityToken()).getElementPath(), true, false)
                        ) {
                    signingSecurityTokens.add((InboundSecurityToken)signedElementSecurityEvent.getSecurityToken());
                }
            }
        }
        return signingSecurityTokens;
    }

    private void setTokenUsage(List<TokenSecurityEvent<? extends InboundSecurityToken>> tokenSecurityEvents, WSSecurityTokenConstants.TokenUsage tokenUsage) throws XMLSecurityException {
        for (int i = 0; i < tokenSecurityEvents.size(); i++) {
            TokenSecurityEvent<? extends InboundSecurityToken> tokenSecurityEvent = tokenSecurityEvents.get(i);
            setTokenUsage(tokenSecurityEvent, tokenUsage);
        }
    }

    private void setTokenUsage(TokenSecurityEvent<? extends InboundSecurityToken> tokenSecurityEvent, WSSecurityTokenConstants.TokenUsage tokenUsage) throws XMLSecurityException {
        tokenSecurityEvent.getSecurityToken().getTokenUsages().remove(WSSecurityTokenConstants.TokenUsage_SupportingTokens);
        tokenSecurityEvent.getSecurityToken().getTokenUsages().remove(WSSecurityTokenConstants.TokenUsage_Signature);
        tokenSecurityEvent.getSecurityToken().getTokenUsages().remove(WSSecurityTokenConstants.TokenUsage_Encryption);
        tokenSecurityEvent.getSecurityToken().addTokenUsage(tokenUsage);
    }

    private List<InboundSecurityToken> isSignedToken(TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent,
                                              Deque<SecurityEvent> securityEventDeque,
                                              HttpsTokenSecurityEvent httpsTokenSecurityEvent) throws XMLSecurityException {
        List<InboundSecurityToken> securityTokenList = new ArrayList<InboundSecurityToken>();
        if (httpsTokenSecurityEvent != null) {
            securityTokenList.add(httpsTokenSecurityEvent.getSecurityToken());
            return securityTokenList;
        }
        for (Iterator<SecurityEvent> iterator = securityEventDeque.iterator(); iterator.hasNext(); ) {
            SecurityEvent securityEvent = iterator.next();
            if (WSSecurityEventConstants.SignedElement.equals(securityEvent.getSecurityEventType())) {
                SignedElementSecurityEvent signedElementSecurityEvent = (SignedElementSecurityEvent) securityEvent;
                if (signedElementSecurityEvent.isSigned()
                        && tokenSecurityEvent.getSecurityToken() != null
                        && signedElementSecurityEvent.getXmlSecEvent() != null
                        && signedElementSecurityEvent.getXmlSecEvent() == 
                            ((InboundSecurityToken)tokenSecurityEvent.getSecurityToken()).getXMLSecEvent()
                        && !securityTokenList.contains((InboundSecurityToken)signedElementSecurityEvent.getSecurityToken())) {
                    securityTokenList.add((InboundSecurityToken)signedElementSecurityEvent.getSecurityToken());
                }
            }
        }
        return securityTokenList;
    }

    private List<InboundSecurityToken> isEncryptedToken(TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent,
                                                 Deque<SecurityEvent> securityEventDeque,
                                                 HttpsTokenSecurityEvent httpsTokenSecurityEvent) throws XMLSecurityException {

        List<InboundSecurityToken> securityTokenList = new ArrayList<InboundSecurityToken>();
        if (httpsTokenSecurityEvent != null) {
            securityTokenList.add(httpsTokenSecurityEvent.getSecurityToken());
            return securityTokenList;
        }
        for (Iterator<SecurityEvent> iterator = securityEventDeque.iterator(); iterator.hasNext(); ) {
            SecurityEvent securityEvent = iterator.next();
            if (WSSecurityEventConstants.EncryptedElement.equals(securityEvent.getSecurityEventType())) {
                EncryptedElementSecurityEvent encryptedElementSecurityEvent = (EncryptedElementSecurityEvent) securityEvent;
                if (encryptedElementSecurityEvent.isEncrypted()
                        && tokenSecurityEvent.getSecurityToken() != null
                        && encryptedElementSecurityEvent.getXmlSecEvent() != null
                        && encryptedElementSecurityEvent.getXmlSecEvent() == 
                            ((InboundSecurityToken)tokenSecurityEvent.getSecurityToken()).getXMLSecEvent()
                        && !securityTokenList.contains((InboundSecurityToken)encryptedElementSecurityEvent.getSecurityToken())) {
                    securityTokenList.add((InboundSecurityToken)encryptedElementSecurityEvent.getSecurityToken());
                }
            }
        }
        return securityTokenList;
    }

    private boolean signsElement(TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent, List<QName> elementPath,
                                 Deque<SecurityEvent> securityEventDeque) throws XMLSecurityException {
        for (Iterator<SecurityEvent> iterator = securityEventDeque.iterator(); iterator.hasNext(); ) {
            SecurityEvent securityEvent = iterator.next();
            if (WSSecurityEventConstants.SignedElement.equals(securityEvent.getSecurityEventType())) {
                SignedElementSecurityEvent signedElementSecurityEvent = (SignedElementSecurityEvent) securityEvent;
                if (signedElementSecurityEvent.isSigned()
                        && signedElementSecurityEvent.getSecurityToken().getId().equals(tokenSecurityEvent.getSecurityToken().getId())
                        && WSSUtils.pathMatches(elementPath, signedElementSecurityEvent.getElementPath(), true, false)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean encryptsElement(TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent, List<QName> elementPath,
                                    Deque<SecurityEvent> securityEventDeque) throws XMLSecurityException {
        for (Iterator<SecurityEvent> iterator = securityEventDeque.iterator(); iterator.hasNext(); ) {
            SecurityEvent securityEvent = iterator.next();
            if (WSSecurityEventConstants.EncryptedElement.equals(securityEvent.getSecurityEventType())) {
                EncryptedElementSecurityEvent encryptedElementSecurityEvent = (EncryptedElementSecurityEvent) securityEvent;
                if (encryptedElementSecurityEvent.isEncrypted()
                        && encryptedElementSecurityEvent.getSecurityToken().getId().equals(tokenSecurityEvent.getSecurityToken().getId())
                        && WSSUtils.pathMatches(elementPath, encryptedElementSecurityEvent.getElementPath(), true, false)) {
                    return true;
                }
            } else if (WSSecurityEventConstants.ContentEncrypted.equals(securityEvent.getSecurityEventType())) {
                ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent = (ContentEncryptedElementSecurityEvent) securityEvent;
                if (contentEncryptedElementSecurityEvent.isEncrypted()
                        && contentEncryptedElementSecurityEvent.getSecurityToken().getId().equals(tokenSecurityEvent.getSecurityToken().getId())
                        && contentEncryptedElementSecurityEvent.getXmlSecEvent() ==
                            ((InboundSecurityToken)tokenSecurityEvent.getSecurityToken()).getXMLSecEvent()
                        && WSSUtils.pathMatches(elementPath, contentEncryptedElementSecurityEvent.getElementPath(), true, false)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public void handleBSPRule(BSPRule bspRule) throws WSSecurityException {
        if (disableBSPEnforcement) {
            return;
        }
        if (!ignoredBSPRules.contains(bspRule)) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.INVALID_SECURITY,
                    "empty",
                    "BSP:" + bspRule.name() + ": " + bspRule.getMsg());
        } else {
            logger.warn("BSP:" + bspRule.name() + ": " + bspRule.getMsg());
        }
    }

    @Override
    public void ignoredBSPRules(List<BSPRule> bspRules) {
        ignoredBSPRules = new ArrayList<BSPRule>(bspRules);
    }

    public boolean isDisableBSPEnforcement() {
        return disableBSPEnforcement;
    }

    public void setDisableBSPEnforcement(boolean disableBSPEnforcement) {
        this.disableBSPEnforcement = disableBSPEnforcement;
    }

    public boolean isAllowRSA15KeyTransportAlgorithm() {
        return allowRSA15KeyTransportAlgorithm;
    }

    public void setAllowRSA15KeyTransportAlgorithm(boolean allowRSA15KeyTransportAlgorithm) {
        this.allowRSA15KeyTransportAlgorithm = allowRSA15KeyTransportAlgorithm;
    }
}
