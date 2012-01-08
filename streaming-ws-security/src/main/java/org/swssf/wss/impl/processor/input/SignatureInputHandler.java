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

import org.swssf.binding.xmldsig.SignatureType;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSUtils;
import org.swssf.wss.ext.WSSecurityContext;
import org.swssf.wss.securityEvent.AlgorithmSuiteSecurityEvent;
import org.swssf.wss.securityEvent.SignatureValueSecurityEvent;
import org.swssf.wss.securityEvent.TokenSecurityEvent;
import org.swssf.xmlsec.ext.InputProcessorChain;
import org.swssf.xmlsec.ext.SecurityToken;
import org.swssf.xmlsec.ext.XMLSecurityException;
import org.swssf.xmlsec.ext.XMLSecurityProperties;
import org.swssf.xmlsec.impl.processor.input.AbstractSignatureInputHandler;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SignatureInputHandler extends AbstractSignatureInputHandler {

    @Override
    protected SignatureVerifier newSignatureVerifier(InputProcessorChain inputProcessorChain,
                                                     XMLSecurityProperties securityProperties,
                                                     final SignatureType signatureType) throws XMLSecurityException {

        final WSSecurityContext securityContext = (WSSecurityContext) inputProcessorChain.getSecurityContext();
        SignatureVerifier signatureVerifier = new SignatureVerifier(signatureType, inputProcessorChain.getSecurityContext(), securityProperties) {
            @Override
            protected void handleSecurityToken(SecurityToken securityToken) throws XMLSecurityException {
                TokenSecurityEvent tokenSecurityEvent = WSSUtils.createTokenSecurityEvent(securityToken);
                tokenSecurityEvent.setTokenUsage(TokenSecurityEvent.TokenUsage.Signature);
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

    @Override
    protected void addSignatureReferenceInputProcessorToChain(InputProcessorChain inputProcessorChain,
                                                              XMLSecurityProperties securityProperties,
                                                              SignatureType signatureType, SecurityToken securityToken) {
        //add processors to verify references
        inputProcessorChain.addProcessor(new SignatureReferenceVerifyInputProcessor(signatureType, securityToken, securityProperties));
    }
}
