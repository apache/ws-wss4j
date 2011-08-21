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
package org.swssf.impl.processor.input;

import org.apache.commons.codec.binary.Base64;
import org.apache.jcs.JCS;
import org.apache.jcs.access.exception.CacheException;
import org.apache.jcs.engine.ElementAttributes;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.TransformationParametersType;
import org.swssf.config.JCEAlgorithmMapper;
import org.swssf.ext.*;
import org.swssf.impl.securityToken.SecurityTokenReference;
import org.swssf.impl.util.DigestOutputStream;
import org.swssf.securityEvent.*;
import org.w3._2000._09.xmldsig_.CanonicalizationMethodType;
import org.w3._2000._09.xmldsig_.ReferenceType;
import org.w3._2000._09.xmldsig_.SignatureType;
import org.w3._2000._09.xmldsig_.TransformType;
import org.xmlsecurity.ns.configuration.AlgorithmType;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SignatureReferenceVerifyInputProcessor extends AbstractInputProcessor {

    private static final String cacheRegionName = "timestamp";

    private static JCS cache;

    static {
        try {
            cache = JCS.getInstance(cacheRegionName);
        } catch (CacheException e) {
            throw new RuntimeException(e);
        }
    }

    private SignatureType signatureType;
    private boolean replayChecked = false;

    public SignatureReferenceVerifyInputProcessor(SignatureType signatureType, SecurityProperties securityProperties) {
        super(securityProperties);
        this.signatureType = signatureType;
        this.getAfterProcessors().add(SignatureInputHandler.class.getName());
        this.getAfterProcessors().add(SignatureReferenceVerifyInputProcessor.class.getName());
    }

    @Override
    public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
        return inputProcessorChain.processHeaderEvent();
    }

    @Override
    public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {

        //this is the earliest possible point to check for an replay attack
        if (!replayChecked) {
            replayChecked = true;
            detectReplayAttack(inputProcessorChain);
        }

        XMLEvent xmlEvent = inputProcessorChain.processEvent();

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            Attribute refId = startElement.getAttributeByName(Constants.ATT_wsu_Id);
            if (refId != null) {
                List<ReferenceType> references = signatureType.getSignedInfo().getReference();
                for (int i = 0; i < references.size(); i++) {
                    ReferenceType referenceType = references.get(i);
                    if (refId.getValue().equals(referenceType.getURI())) {
                        logger.debug("Found signature reference: " + refId.getValue() + " on element" + startElement.getName());
                        if (referenceType.isProcessed()) {
                            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, "duplicateId");
                        }
                        InternalSignatureReferenceVerifier internalSignatureReferenceVerifier =
                                new InternalSignatureReferenceVerifier(getSecurityProperties(), inputProcessorChain, referenceType, startElement.getName());
                        if (!internalSignatureReferenceVerifier.isFinished()) {
                            internalSignatureReferenceVerifier.processEvent(xmlEvent, inputProcessorChain);
                            inputProcessorChain.addProcessor(internalSignatureReferenceVerifier);
                        }
                        referenceType.setProcessed(true);
                        inputProcessorChain.getDocumentContext().setIsInSignedContent();

                        //fire a SecurityEvent:
                        if (inputProcessorChain.getDocumentContext().getDocumentLevel() == 3
                                && inputProcessorChain.getDocumentContext().isInSOAPHeader()) {
                            SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(SecurityEvent.Event.SignedPart, false);
                            signedPartSecurityEvent.setElement(startElement.getName());
                            inputProcessorChain.getSecurityContext().registerSecurityEvent(signedPartSecurityEvent);
                        } else {
                            SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(SecurityEvent.Event.SignedElement, false);
                            signedElementSecurityEvent.setElement(startElement.getName());
                            inputProcessorChain.getSecurityContext().registerSecurityEvent(signedElementSecurityEvent);
                        }
                    }
                }
            }
        }

        return xmlEvent;
    }

    private void detectReplayAttack(InputProcessorChain inputProcessorChain) throws WSSecurityException {
        TimestampSecurityEvent timestampSecurityEvent = inputProcessorChain.getSecurityContext().get(Constants.PROP_TIMESTAMP_SECURITYEVENT);
        if (timestampSecurityEvent != null) {
            final String cacheKey = String.valueOf(timestampSecurityEvent.getCreated().getTimeInMillis()) + signatureType.getSignatureValue().getRawValue();
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
    public void doFinal(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
        List<ReferenceType> references = signatureType.getSignedInfo().getReference();
        for (int i = 0; i < references.size(); i++) {
            ReferenceType referenceType = references.get(i);
            if (!referenceType.isProcessed()) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, "unprocessedSignatureReferences");
            }
        }
        inputProcessorChain.doFinal();
    }

    class InternalSignatureReferenceVerifier extends AbstractInputProcessor {
        private ReferenceType referenceType;

        private Transformer transformer;
        private DigestOutputStream digestOutputStream;
        private OutputStream bufferedDigestOutputStream;
        private QName startElement;
        private int elementCounter = 0;
        private boolean finished = false;

        public InternalSignatureReferenceVerifier(SecurityProperties securityProperties, InputProcessorChain inputProcessorChain, ReferenceType referenceType, QName startElement) throws WSSecurityException {
            super(securityProperties);
            this.getAfterProcessors().add(SignatureReferenceVerifyInputProcessor.class.getName());
            this.startElement = startElement;
            this.referenceType = referenceType;
            try {
                createMessageDigest(inputProcessorChain.getSecurityContext());
                buildTransformerChain(referenceType, inputProcessorChain);
            } catch (Exception e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
            }
        }

        private void createMessageDigest(SecurityContext securityContext) throws WSSecurityException, NoSuchAlgorithmException, NoSuchProviderException {
            AlgorithmType digestAlgorithm = JCEAlgorithmMapper.getAlgorithmMapping(referenceType.getDigestMethod().getAlgorithm());

            AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent(SecurityEvent.Event.AlgorithmSuite);
            algorithmSuiteSecurityEvent.setAlgorithmURI(digestAlgorithm.getURI());
            algorithmSuiteSecurityEvent.setKeyUsage(Constants.KeyUsage.Dig);
            securityContext.registerSecurityEvent(algorithmSuiteSecurityEvent);

            MessageDigest messageDigest = MessageDigest.getInstance(digestAlgorithm.getJCEName(), digestAlgorithm.getJCEProvider());
            this.digestOutputStream = new DigestOutputStream(messageDigest);
            this.bufferedDigestOutputStream = new BufferedOutputStream(this.digestOutputStream);
        }

        private void buildTransformerChain(ReferenceType referenceType, InputProcessorChain inputProcessorChain) throws WSSecurityException, XMLStreamException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
            List<TransformType> transformTypeList = referenceType.getTransforms().getTransform();

            String algorithm = null;
            Transformer parentTransformer = null;
            for (int i = transformTypeList.size() - 1; i >= 0; i--) {
                TransformType transformType = transformTypeList.get(i);

                if (transformType.getTransformationParametersType() != null) {
                    TransformationParametersType transformationParametersType = transformType.getTransformationParametersType();
                    final CanonicalizationMethodType canonicalizationMethodType = transformationParametersType.getCanonicalizationMethodType();
                    if (canonicalizationMethodType != null) {
                        algorithm = canonicalizationMethodType.getAlgorithm();
                        String inclusiveNamespaces = canonicalizationMethodType.getInclusiveNamespaces();
                        if (Constants.SOAPMESSAGE_NS10_STRTransform.equals(transformType.getAlgorithm())) {
                            if (inclusiveNamespaces == null) {
                                inclusiveNamespaces = "#default";
                            } else {
                                inclusiveNamespaces = "#default " + inclusiveNamespaces;
                            }
                        }
                        parentTransformer = Utils.getTransformer(inclusiveNamespaces, this.bufferedDigestOutputStream, algorithm);
                    }
                }
                algorithm = transformType.getAlgorithm();

                AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent(SecurityEvent.Event.AlgorithmSuite);
                algorithmSuiteSecurityEvent.setAlgorithmURI(algorithm);
                algorithmSuiteSecurityEvent.setKeyUsage(Constants.KeyUsage.C14n);
                inputProcessorChain.getSecurityContext().registerSecurityEvent(algorithmSuiteSecurityEvent);

                if (parentTransformer != null) {
                    parentTransformer = Utils.getTransformer(parentTransformer, transformType.getInclusiveNamespaces(), algorithm);
                } else {
                    parentTransformer = Utils.getTransformer(transformType.getInclusiveNamespaces(), this.bufferedDigestOutputStream, algorithm);
                }
            }

            this.transformer = parentTransformer;

            if (Constants.SOAPMESSAGE_NS10_STRTransform.equals(algorithm)) {
                SecurityTokenProvider securityTokenProvider = inputProcessorChain.getSecurityContext().getSecurityTokenProvider(referenceType.getURI());
                if (securityTokenProvider == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "noReference");
                }
                SecurityToken securityToken = securityTokenProvider.getSecurityToken(getSecurityProperties().getSignatureVerificationCrypto());
                if (!(securityToken instanceof SecurityTokenReference)) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.UNSUPPORTED_SECURITY_TOKEN);
                }
                SecurityTokenReference securityTokenReference = (SecurityTokenReference) securityToken;
                this.startElement = securityTokenReference.getXmlEvents().getLast().asStartElement().getName();
                Iterator<XMLEvent> xmlEventIterator = securityTokenReference.getXmlEvents().descendingIterator();
                while (xmlEventIterator.hasNext()) {
                    processEvent(xmlEventIterator.next(), inputProcessorChain);
                }
            }
        }

        @Override
        public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
            return inputProcessorChain.processHeaderEvent();
        }

        @Override
        public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
            XMLEvent xmlEvent = inputProcessorChain.processEvent();
            processEvent(xmlEvent, inputProcessorChain);
            return xmlEvent;
        }

        protected void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {

            transformer.transform(xmlEvent);

            if (xmlEvent.isStartElement()) {
                elementCounter++;
            } else if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                elementCounter--;

                if (endElement.getName().equals(startElement) && elementCounter == 0) {
                    try {
                        bufferedDigestOutputStream.close();
                    } catch (IOException e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
                    }

                    byte[] calculatedDigest = this.digestOutputStream.getDigestValue();
                    byte[] storedDigest = Base64.decodeBase64(referenceType.getDigestValue());

                    if (logger.isDebugEnabled()) {
                        logger.debug("Calculated Digest: " + new String(Base64.encodeBase64(calculatedDigest)));
                        logger.debug("Stored Digest: " + new String(Base64.encodeBase64(storedDigest)));
                    }

                    if (!MessageDigest.isEqual(storedDigest, calculatedDigest)) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, "digestVerificationFailed", referenceType.getURI());
                    }
                    inputProcessorChain.removeProcessor(this);
                    inputProcessorChain.getDocumentContext().unsetIsInSignedContent();
                    finished = true;
                }
            }
        }

        public boolean isFinished() {
            return finished;
        }
    }
}
