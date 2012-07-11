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
package org.swssf.wss.impl.processor.input;

import org.apache.xml.security.binding.excc14n.InclusiveNamespaces;
import org.swssf.binding.wss10.SecurityTokenReferenceType;
import org.apache.xml.security.binding.xmldsig.CanonicalizationMethodType;
import org.apache.xml.security.binding.xmldsig.KeyInfoType;
import org.apache.xml.security.binding.xmldsig.ManifestType;
import org.apache.xml.security.binding.xmldsig.ObjectType;
import org.apache.xml.security.binding.xmldsig.SignatureType;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSUtils;
import org.swssf.wss.ext.WSSecurityContext;
import org.swssf.wss.ext.WSSecurityException;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.impl.processor.input.AbstractSignatureInputHandler;
import org.apache.xml.security.stax.impl.securityToken.SecurityTokenFactory;
import org.apache.xml.security.stax.securityEvent.AlgorithmSuiteSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SignatureValueSecurityEvent;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class WSSSignatureInputHandler extends AbstractSignatureInputHandler {

    @Override
    protected SignatureVerifier newSignatureVerifier(final InputProcessorChain inputProcessorChain,
                                                     final XMLSecurityProperties securityProperties,
                                                     final SignatureType signatureType) throws XMLSecurityException {
        if (signatureType.getSignedInfo() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY);
        }
        if (signatureType.getSignedInfo().getSignatureMethod() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY);
        }
        if (signatureType.getSignedInfo().getCanonicalizationMethod() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY);
        }
        if (signatureType.getSignatureValue() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY);
        }
        if (signatureType.getKeyInfo() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY);
        }
        checkBSPCompliance(inputProcessorChain, signatureType);

        final WSSecurityContext securityContext = (WSSecurityContext) inputProcessorChain.getSecurityContext();
        final SignatureVerifier signatureVerifier = new WSSSignatureVerifier(signatureType, inputProcessorChain.getSecurityContext(), securityProperties) {
            @Override
            protected void handleSecurityToken(SecurityToken securityToken) throws XMLSecurityException {
                //we have to emit a TokenSecurityEvent here too since it could be an embedded token
                securityToken.addTokenUsage(SecurityToken.TokenUsage.Signature);
                TokenSecurityEvent tokenSecurityEvent = WSSUtils.createTokenSecurityEvent(securityToken);
                securityContext.registerSecurityEvent(tokenSecurityEvent);

                SignatureValueSecurityEvent signatureValueSecurityEvent = new SignatureValueSecurityEvent();
                signatureValueSecurityEvent.setSignatureValue(signatureType.getSignatureValue().getValue());
                securityContext.registerSecurityEvent(signatureValueSecurityEvent);

                AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent();
                algorithmSuiteSecurityEvent.setAlgorithmURI(signatureType.getSignedInfo().getCanonicalizationMethod().getAlgorithm());
                algorithmSuiteSecurityEvent.setKeyUsage(WSSConstants.C14n);
                securityContext.registerSecurityEvent(algorithmSuiteSecurityEvent);
                super.handleSecurityToken(securityToken);
            }
        };

        return signatureVerifier;
    }

    private void checkBSPCompliance(InputProcessorChain inputProcessorChain, SignatureType signatureType) throws WSSecurityException {
        String algorithm = signatureType.getSignedInfo().getSignatureMethod().getAlgorithm();
        final WSSecurityContext securityContext = (WSSecurityContext) inputProcessorChain.getSecurityContext();
        if (!WSSConstants.NS_XMLDSIG_HMACSHA1.equals(algorithm) && !WSSConstants.NS_XMLDSIG_RSASHA1.equals(algorithm)) {
            securityContext.handleBSPRule(WSSConstants.BSPRule.R5421);
        }
        //todo test:
        BigInteger hmacOutputLength = XMLSecurityUtils.getQNameType(
                signatureType.getSignedInfo().getSignatureMethod().getContent(),
                WSSConstants.TAG_dsig_HMACOutputLength);
        if (hmacOutputLength != null) {
            securityContext.handleBSPRule(WSSConstants.BSPRule.R5401);
        }

        List<Object> keyInfoContent = signatureType.getKeyInfo().getContent();
        if (keyInfoContent.size() != 1) {
            securityContext.handleBSPRule(WSSConstants.BSPRule.R5402);
        }

        SecurityTokenReferenceType securityTokenReferenceType = XMLSecurityUtils.getQNameType(keyInfoContent,
                WSSConstants.TAG_wsse_SecurityTokenReference);
        if (securityTokenReferenceType == null) {
            securityContext.handleBSPRule(WSSConstants.BSPRule.R5417);
        }

        Iterator<ObjectType> objectTypeIterator = signatureType.getObject().iterator();
        while (objectTypeIterator.hasNext()) {
            ObjectType objectType = objectTypeIterator.next();
            ManifestType manifestType = XMLSecurityUtils.getQNameType(objectType.getContent(), WSSConstants.TAG_dsig_Manifest);
            if (manifestType != null) {
                securityContext.handleBSPRule(WSSConstants.BSPRule.R5403);
            }
        }

        CanonicalizationMethodType canonicalizationMethodType = signatureType.getSignedInfo().getCanonicalizationMethod();
        if (!WSSConstants.NS_C14N_EXCL.equals(canonicalizationMethodType.getAlgorithm())) {
            securityContext.handleBSPRule(WSSConstants.BSPRule.R5404);
        }

        InclusiveNamespaces inclusiveNamespacesType = XMLSecurityUtils.getQNameType(canonicalizationMethodType.getContent(),
                WSSConstants.TAG_c14nExcl_InclusiveNamespaces);
        if (inclusiveNamespacesType != null && inclusiveNamespacesType.getPrefixList().size() == 0) {
            securityContext.handleBSPRule(WSSConstants.BSPRule.R5406);
        }
    }

    @Override
    protected void addSignatureReferenceInputProcessorToChain(InputProcessorChain inputProcessorChain,
                                                              XMLSecurityProperties securityProperties,
                                                              SignatureType signatureType, SecurityToken securityToken) throws XMLSecurityException {
        //add processors to verify references
        inputProcessorChain.addProcessor(
                new WSSSignatureReferenceVerifyInputProcessor(signatureType, securityToken, securityProperties,
                        (WSSecurityContext) inputProcessorChain.getSecurityContext()));
    }
    
    public class WSSSignatureVerifier extends SignatureVerifier {
        
        public WSSSignatureVerifier(SignatureType signatureType, SecurityContext securityContext,
                                    XMLSecurityProperties securityProperties) throws XMLSecurityException {
            super(signatureType, securityContext, securityProperties);
        }
        
        protected SecurityToken retrieveSecurityToken(KeyInfoType keyInfoType,
                                                      XMLSecurityProperties securityProperties,
                                                      SecurityContext securityContext) throws XMLSecurityException {
            return SecurityTokenFactory.getInstance().getSecurityToken(keyInfoType, SecurityToken.KeyInfoUsage.SIGNATURE_VERIFICATION,
                                                                securityProperties, securityContext);
            
        }
    }
}
