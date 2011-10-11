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

import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSecurityContext;
import org.swssf.wss.securityEvent.AlgorithmSuiteSecurityEvent;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.SignatureTokenSecurityEvent;
import org.swssf.xmlsec.ext.*;
import org.swssf.xmlsec.impl.processor.input.AbstractSignatureInputHandler;
import org.w3._2000._09.xmldsig_.*;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Deque;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SignatureInputHandler extends AbstractSignatureInputHandler {

    public SignatureInputHandler(InputProcessorChain inputProcessorChain, XMLSecurityProperties securityProperties,
                                 Deque<XMLEvent> eventQueue, Integer index) throws XMLSecurityException, XMLStreamException {

        super(inputProcessorChain, securityProperties, eventQueue, index);
    }

    @Override
    protected Parseable getParseable(StartElement startElement) {
        return new SignatureType(startElement) {
            @Override
            protected KeyInfoType newKeyInfoType(StartElement startElement) {
                return new org.w3._2000._09.xmldsig_.wss.KeyInfoType(startElement);
            }

            @Override
            protected SignedInfoType newSignedInfoType(StartElement startElement) {
                return new org.w3._2000._09.xmldsig_.wss.SignedInfoType(startElement) {
                    @Override
                    protected ReferenceType newReferenceType(StartElement startElement) {
                        return new org.w3._2000._09.xmldsig_.wss.ReferenceType(startElement) {
                            @Override
                            protected TransformsType newTransformsType(StartElement startElement) {
                                return new org.w3._2000._09.xmldsig_.wss.TransformsType(startElement) {
                                    @Override
                                    protected TransformType newTransformType(StartElement startElement) {
                                        return new org.w3._2000._09.xmldsig_.wss.TransformType(startElement);
                                    }
                                };
                            }
                        };
                    }
                };
            }
        };
    }

    @Override
    protected void addSignatureReferenceInputProcessorToChain(InputProcessorChain inputProcessorChain, XMLSecurityProperties securityProperties, SignatureType signatureType) {
        //add processors to verify references
        inputProcessorChain.addProcessor(new SignatureReferenceVerifyInputProcessor(signatureType, securityProperties));
    }

    @Override
    protected SignatureVerifier newSignatureVerifier(InputProcessorChain inputProcessorChain,
                                                     XMLSecurityProperties securityProperties,
                                                     final SignatureType signatureType) throws XMLSecurityException {

        final WSSecurityContext securityContext = (WSSecurityContext) inputProcessorChain.getSecurityContext();
        SignatureVerifier signatureVerifier = new SignatureVerifier(signatureType, inputProcessorChain.getSecurityContext(), securityProperties) {
            @Override
            protected void createSignatureAlgorithm(SecurityToken securityToken) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, CertificateException, XMLSecurityException {
                SignatureTokenSecurityEvent signatureTokenSecurityEvent = new SignatureTokenSecurityEvent(SecurityEvent.Event.SignatureToken);
                signatureTokenSecurityEvent.setSecurityToken(securityToken);
                signatureTokenSecurityEvent.setSignatureValue(signatureType.getSignatureValue().getValue());
                securityContext.registerSecurityEvent(signatureTokenSecurityEvent);

                AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent(SecurityEvent.Event.AlgorithmSuite);
                algorithmSuiteSecurityEvent.setAlgorithmURI(signatureType.getSignedInfo().getCanonicalizationMethod().getAlgorithm());
                algorithmSuiteSecurityEvent.setKeyUsage(WSSConstants.C14n);
                securityContext.registerSecurityEvent(algorithmSuiteSecurityEvent);
                super.createSignatureAlgorithm(securityToken);
            }
        };

        return signatureVerifier;
    }
}
