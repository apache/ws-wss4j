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
package org.apache.wss4j.stax.impl.processor.input;

import org.apache.wss4j.binding.wss10.SecurityTokenReferenceType;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.ext.WSSUtils;
import org.apache.wss4j.stax.ext.WSSecurityContext;
import org.apache.wss4j.stax.validate.SignatureTokenValidator;
import org.apache.wss4j.stax.validate.SignatureTokenValidatorImpl;
import org.apache.xml.security.binding.excc14n.InclusiveNamespaces;
import org.apache.xml.security.binding.xmldsig.CanonicalizationMethodType;
import org.apache.xml.security.binding.xmldsig.ManifestType;
import org.apache.xml.security.binding.xmldsig.ObjectType;
import org.apache.xml.security.binding.xmldsig.SignatureType;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.processor.input.AbstractSignatureInputHandler;
import org.apache.xml.security.stax.impl.securityToken.SecurityTokenFactory;
import org.apache.xml.security.stax.securityEvent.AlgorithmSuiteSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SignatureValueSecurityEvent;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;

import java.math.BigInteger;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;

public class WSSSignatureInputHandler extends AbstractSignatureInputHandler {

    @Override
    public void handle(InputProcessorChain inputProcessorChain, XMLSecurityProperties securityProperties,
                       Deque<XMLSecEvent> eventQueue, Integer index) throws XMLSecurityException {
        try {
            super.handle(inputProcessorChain, securityProperties, eventQueue, index);
        } catch (WSSecurityException e) {
            throw e;
        } catch (XMLSecurityException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
        }
    }

    @Override
    protected SignatureVerifier newSignatureVerifier(
            final InputProcessorChain inputProcessorChain, final XMLSecurityProperties securityProperties,
            final SignatureType signatureType) throws XMLSecurityException {

        if (signatureType.getKeyInfo() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY);
        }
        checkBSPCompliance(inputProcessorChain, signatureType);

        final WSSecurityContext securityContext = (WSSecurityContext) inputProcessorChain.getSecurityContext();

        SignatureValueSecurityEvent signatureValueSecurityEvent = new SignatureValueSecurityEvent();
        signatureValueSecurityEvent.setSignatureValue(signatureType.getSignatureValue().getValue());
        signatureValueSecurityEvent.setCorrelationID(signatureType.getId());
        securityContext.registerSecurityEvent(signatureValueSecurityEvent);

        AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent();
        algorithmSuiteSecurityEvent.setAlgorithmURI(signatureType.getSignedInfo().getCanonicalizationMethod().getAlgorithm());
        algorithmSuiteSecurityEvent.setKeyUsage(WSSConstants.C14n);
        algorithmSuiteSecurityEvent.setCorrelationID(signatureType.getId());
        securityContext.registerSecurityEvent(algorithmSuiteSecurityEvent);

        return new WSSSignatureVerifier(signatureType, inputProcessorChain.getSecurityContext(), securityProperties);
    }

    private void checkBSPCompliance(InputProcessorChain inputProcessorChain, SignatureType signatureType) throws WSSecurityException {
        String algorithm = signatureType.getSignedInfo().getSignatureMethod().getAlgorithm();
        final WSSecurityContext securityContext = (WSSecurityContext) inputProcessorChain.getSecurityContext();
        if (!WSSConstants.NS_XMLDSIG_HMACSHA1.equals(algorithm) && !WSSConstants.NS_XMLDSIG_RSASHA1.equals(algorithm)) {
            securityContext.handleBSPRule(BSPRule.R5421);
        }
        //todo test:
        BigInteger hmacOutputLength = XMLSecurityUtils.getQNameType(
                signatureType.getSignedInfo().getSignatureMethod().getContent(),
                WSSConstants.TAG_dsig_HMACOutputLength);
        if (hmacOutputLength != null) {
            securityContext.handleBSPRule(BSPRule.R5401);
        }

        List<Object> keyInfoContent = signatureType.getKeyInfo().getContent();
        if (keyInfoContent.size() != 1) {
            securityContext.handleBSPRule(BSPRule.R5402);
        }

        SecurityTokenReferenceType securityTokenReferenceType = XMLSecurityUtils.getQNameType(keyInfoContent,
                WSSConstants.TAG_wsse_SecurityTokenReference);
        if (securityTokenReferenceType == null) {
            securityContext.handleBSPRule(BSPRule.R5417);
        }

        Iterator<ObjectType> objectTypeIterator = signatureType.getObject().iterator();
        while (objectTypeIterator.hasNext()) {
            ObjectType objectType = objectTypeIterator.next();
            ManifestType manifestType = XMLSecurityUtils.getQNameType(objectType.getContent(), WSSConstants.TAG_dsig_Manifest);
            if (manifestType != null) {
                securityContext.handleBSPRule(BSPRule.R5403);
            }
        }

        CanonicalizationMethodType canonicalizationMethodType = signatureType.getSignedInfo().getCanonicalizationMethod();
        if (!WSSConstants.NS_C14N_EXCL.equals(canonicalizationMethodType.getAlgorithm())) {
            securityContext.handleBSPRule(BSPRule.R5404);
        }

        InclusiveNamespaces inclusiveNamespacesType = XMLSecurityUtils.getQNameType(canonicalizationMethodType.getContent(),
                WSSConstants.TAG_c14nExcl_InclusiveNamespaces);
        if (inclusiveNamespacesType != null && inclusiveNamespacesType.getPrefixList().size() == 0) {
            securityContext.handleBSPRule(BSPRule.R5406);
        }
    }

    @Override
    protected void addSignatureReferenceInputProcessorToChain(
            InputProcessorChain inputProcessorChain, XMLSecurityProperties securityProperties,
            SignatureType signatureType, SecurityToken securityToken) throws XMLSecurityException {

        try {
            //add processors to verify references
            inputProcessorChain.addProcessor(
                    new WSSSignatureReferenceVerifyInputProcessor(inputProcessorChain, signatureType,
                            securityToken, securityProperties));
        } catch (WSSecurityException e) {
            throw e;
        } catch (XMLSecurityException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
        }
    }

    public class WSSSignatureVerifier extends SignatureVerifier {

        public WSSSignatureVerifier(SignatureType signatureType, SecurityContext securityContext,
                                    XMLSecurityProperties securityProperties) throws XMLSecurityException {
            super(signatureType, securityContext, securityProperties);
        }

        @Override
        protected SecurityToken retrieveSecurityToken(SignatureType signatureType,
                                                      XMLSecurityProperties securityProperties,
                                                      SecurityContext securityContext) throws XMLSecurityException {

            SecurityToken securityToken = SecurityTokenFactory.getInstance().getSecurityToken(
                    signatureType.getKeyInfo(), SecurityToken.KeyInfoUsage.SIGNATURE_VERIFICATION,
                    securityProperties, securityContext);

            SignatureTokenValidator signatureTokenValidator = ((WSSSecurityProperties) securityProperties).getValidator(WSSConstants.TAG_dsig_Signature);
            if (signatureTokenValidator == null) {
                signatureTokenValidator = new SignatureTokenValidatorImpl();
            }
            signatureTokenValidator.validate(securityToken, (WSSSecurityProperties) securityProperties);

            //todo element path?
            //we have to emit a TokenSecurityEvent here too since it could be an embedded token
            securityToken.addTokenUsage(SecurityToken.TokenUsage.Signature);
            TokenSecurityEvent tokenSecurityEvent = WSSUtils.createTokenSecurityEvent(securityToken, signatureType.getId());
            securityContext.registerSecurityEvent(tokenSecurityEvent);

            return securityToken;

        }
    }
}
