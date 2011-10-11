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

import org.apache.jcs.JCS;
import org.apache.jcs.access.exception.CacheException;
import org.apache.jcs.engine.ElementAttributes;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.TransformationParametersType;
import org.swssf.wss.ext.*;
import org.swssf.wss.impl.securityToken.SecurityTokenReference;
import org.swssf.wss.securityEvent.*;
import org.swssf.xmlsec.ext.*;
import org.swssf.xmlsec.impl.processor.input.AbstractSignatureReferenceVerifyInputProcessor;
import org.w3._2000._09.xmldsig_.CanonicalizationMethodType;
import org.w3._2000._09.xmldsig_.ReferenceType;
import org.w3._2000._09.xmldsig_.SignatureType;
import org.xmlsecurity.ns.configuration.AlgorithmType;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SignatureReferenceVerifyInputProcessor extends AbstractSignatureReferenceVerifyInputProcessor {

    private static final String cacheRegionName = "timestamp";

    private static JCS cache;

    static {
        try {
            cache = JCS.getInstance(cacheRegionName);
        } catch (CacheException e) {
            throw new RuntimeException(e);
        }
    }

    private boolean replayChecked = false;

    public SignatureReferenceVerifyInputProcessor(SignatureType signatureType, XMLSecurityProperties securityProperties) {
        super(signatureType, securityProperties);
        this.getAfterProcessors().add(SignatureReferenceVerifyInputProcessor.class.getName());
    }

    @Override
    public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {

        //this is the earliest possible point to check for an replay attack
        if (!replayChecked) {
            replayChecked = true;
            detectReplayAttack(inputProcessorChain);
        }

        XMLEvent xmlEvent = inputProcessorChain.processEvent();

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();
            ReferenceType referenceType = matchesReferenceId(startElement);
            if (referenceType != null) {

                if (referenceType.isProcessed()) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, "duplicateId");
                }
                InternalSignatureReferenceVerifier internalSignatureReferenceVerifier =
                        new InternalSignatureReferenceVerifier(((WSSSecurityProperties) getSecurityProperties()), inputProcessorChain, referenceType, startElement.getName());
                if (!internalSignatureReferenceVerifier.isFinished()) {
                    internalSignatureReferenceVerifier.processEvent(xmlEvent, inputProcessorChain);
                    inputProcessorChain.addProcessor(internalSignatureReferenceVerifier);
                }
                referenceType.setProcessed(true);
                inputProcessorChain.getDocumentContext().setIsInSignedContent();

                //fire a SecurityEvent:
                if (inputProcessorChain.getDocumentContext().getDocumentLevel() == 3
                        && ((WSSDocumentContext) inputProcessorChain.getDocumentContext()).isInSOAPHeader()) {
                    SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(SecurityEvent.Event.SignedPart, false);
                    signedPartSecurityEvent.setElement(startElement.getName());
                    ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(signedPartSecurityEvent);
                } else {
                    SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(SecurityEvent.Event.SignedElement, false);
                    signedElementSecurityEvent.setElement(startElement.getName());
                    ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(signedElementSecurityEvent);
                }
            }
        }
        return xmlEvent;
    }

    private void detectReplayAttack(InputProcessorChain inputProcessorChain) throws WSSecurityException {
        TimestampSecurityEvent timestampSecurityEvent = inputProcessorChain.getSecurityContext().get(WSSConstants.PROP_TIMESTAMP_SECURITYEVENT);
        if (timestampSecurityEvent != null) {
            final String cacheKey = String.valueOf(timestampSecurityEvent.getCreated().getTimeInMillis()) + getSignatureType().getSignatureValue().getRawValue();
            if (cache.get(cacheKey) != null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.MESSAGE_EXPIRED);
            }
            ElementAttributes elementAttributes = new ElementAttributes();
            if (timestampSecurityEvent.getExpires() != null) {
                long lifeTime = timestampSecurityEvent.getExpires().getTime().getTime() - new Date().getTime();
                elementAttributes.setMaxLifeSeconds(lifeTime / 1000);
            } else {
                elementAttributes.setMaxLifeSeconds(300);
            }
            try {
                cache.put(cacheKey, timestampSecurityEvent.getCreated(), elementAttributes);
            } catch (CacheException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
            }
        }
    }

    @Override
    public Attribute getReferenceIDAttribute(StartElement startElement) {
        Attribute attribute = startElement.getAttributeByName(WSSConstants.ATT_wsu_Id);
        if (attribute == null) {
            attribute = super.getReferenceIDAttribute(startElement);
        }
        return attribute;
    }

    class InternalSignatureReferenceVerifier extends AbstractSignatureReferenceVerifyInputProcessor.InternalSignatureReferenceVerifier {

        InternalSignatureReferenceVerifier(WSSSecurityProperties securityProperties, InputProcessorChain inputProcessorChain, ReferenceType referenceType, QName startElement) throws XMLSecurityException {
            super(securityProperties, inputProcessorChain, referenceType, startElement);
            this.getAfterProcessors().add(SignatureReferenceVerifyInputProcessor.class.getName());
        }

        protected AlgorithmType createMessageDigest(SecurityContext securityContext) throws XMLSecurityException, NoSuchAlgorithmException, NoSuchProviderException {
            AlgorithmType digestAlgorithm = super.createMessageDigest(securityContext);

            AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent(SecurityEvent.Event.AlgorithmSuite);
            algorithmSuiteSecurityEvent.setAlgorithmURI(digestAlgorithm.getURI());
            algorithmSuiteSecurityEvent.setKeyUsage(WSSConstants.Dig);
            ((WSSecurityContext) securityContext).registerSecurityEvent(algorithmSuiteSecurityEvent);
            return digestAlgorithm;
        }

        protected void buildTransformerChain(ReferenceType referenceType, InputProcessorChain inputProcessorChain) throws XMLSecurityException, XMLStreamException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
            List<org.w3._2000._09.xmldsig_.wss.TransformType> transformTypeList = (List<org.w3._2000._09.xmldsig_.wss.TransformType>) (List<?>) referenceType.getTransforms().getTransform();

            String algorithm = null;
            Transformer parentTransformer = null;
            for (int i = transformTypeList.size() - 1; i >= 0; i--) {
                org.w3._2000._09.xmldsig_.wss.TransformType transformType = transformTypeList.get(i);

                if (transformType.getTransformationParametersType() != null) {
                    TransformationParametersType transformationParametersType = transformType.getTransformationParametersType();
                    final CanonicalizationMethodType canonicalizationMethodType = transformationParametersType.getCanonicalizationMethodType();
                    if (canonicalizationMethodType != null) {
                        algorithm = canonicalizationMethodType.getAlgorithm();
                        String inclusiveNamespaces = canonicalizationMethodType.getInclusiveNamespaces();
                        if (WSSConstants.SOAPMESSAGE_NS10_STRTransform.equals(transformType.getAlgorithm())) {
                            if (inclusiveNamespaces == null) {
                                inclusiveNamespaces = "#default";
                            } else {
                                inclusiveNamespaces = "#default " + inclusiveNamespaces;
                            }
                        }
                        parentTransformer = WSSUtils.getTransformer(inclusiveNamespaces, this.getBufferedDigestOutputStream(), algorithm);
                    }
                }
                algorithm = transformType.getAlgorithm();

                AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent(SecurityEvent.Event.AlgorithmSuite);
                algorithmSuiteSecurityEvent.setAlgorithmURI(algorithm);
                algorithmSuiteSecurityEvent.setKeyUsage(WSSConstants.C14n);
                ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(algorithmSuiteSecurityEvent);

                if (parentTransformer != null) {
                    parentTransformer = WSSUtils.getTransformer(parentTransformer, transformType.getInclusiveNamespaces(), algorithm);
                } else {
                    parentTransformer = WSSUtils.getTransformer(transformType.getInclusiveNamespaces(), this.getBufferedDigestOutputStream(), algorithm);
                }
            }

            this.setTransformer(parentTransformer);

            if (WSSConstants.SOAPMESSAGE_NS10_STRTransform.equals(algorithm)) {
                SecurityTokenProvider securityTokenProvider = inputProcessorChain.getSecurityContext().getSecurityTokenProvider(referenceType.getURI());
                if (securityTokenProvider == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "noReference");
                }
                SecurityToken securityToken = securityTokenProvider.getSecurityToken(getSecurityProperties().getSignatureVerificationCrypto());
                if (!(securityToken instanceof SecurityTokenReference)) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.UNSUPPORTED_SECURITY_TOKEN);
                }
                SecurityTokenReference securityTokenReference = (SecurityTokenReference) securityToken;
                this.setStartElement(securityTokenReference.getXmlEvents().getLast().asStartElement().getName());
                Iterator<XMLEvent> xmlEventIterator = securityTokenReference.getXmlEvents().descendingIterator();
                while (xmlEventIterator.hasNext()) {
                    processEvent(xmlEventIterator.next(), inputProcessorChain);
                }
            }
        }

        @Override
        protected void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
            super.processEvent(xmlEvent, inputProcessorChain);
        }
    }
}
