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

import org.apache.wss4j.binding.wss10.TransformationParametersType;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.cache.ReplayCache;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.securityToken.SecurityTokenReference;
import org.apache.xml.security.binding.excc14n.InclusiveNamespaces;
import org.apache.xml.security.binding.xmldsig.CanonicalizationMethodType;
import org.apache.xml.security.binding.xmldsig.ReferenceType;
import org.apache.xml.security.binding.xmldsig.SignatureType;
import org.apache.xml.security.binding.xmldsig.TransformType;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.processor.input.AbstractSignatureReferenceVerifyInputProcessor;
import org.apache.xml.security.stax.securityEvent.AlgorithmSuiteSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SignedElementSecurityEvent;
import org.apache.wss4j.stax.ext.*;
import org.apache.wss4j.stax.securityEvent.SignedPartSecurityEvent;
import org.apache.wss4j.stax.securityEvent.TimestampSecurityEvent;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenProvider;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

public class WSSSignatureReferenceVerifyInputProcessor extends AbstractSignatureReferenceVerifyInputProcessor {

    private boolean replayChecked = false;

    public WSSSignatureReferenceVerifyInputProcessor(InputProcessorChain inputProcessorChain,
            SignatureType signatureType, InboundSecurityToken inboundSecurityToken,
            XMLSecurityProperties securityProperties) throws XMLSecurityException {
        super(inputProcessorChain, signatureType, inboundSecurityToken, securityProperties);
        this.addAfterProcessor(WSSSignatureReferenceVerifyInputProcessor.class.getName());

        checkBSPCompliance((WSInboundSecurityContext)inputProcessorChain.getSecurityContext());
    }

    private void checkBSPCompliance(WSInboundSecurityContext securityContext) throws WSSecurityException {
        List<ReferenceType> references = getSignatureType().getSignedInfo().getReference();
        for (int i = 0; i < references.size(); i++) {
            ReferenceType referenceType = references.get(i);
            if (referenceType.getTransforms() == null) {
                securityContext.handleBSPRule(BSPRule.R5416);
            } else if (referenceType.getTransforms().getTransform().size() == 0) {
                securityContext.handleBSPRule(BSPRule.R5411);
            } else {
                List<TransformType> transformTypes = referenceType.getTransforms().getTransform();
                for (int j = 0; j < transformTypes.size(); j++) {
                    TransformType transformType = transformTypes.get(j);
                    final String algorithm = transformType.getAlgorithm();
                    if (!WSSConstants.NS_C14N_EXCL.equals(algorithm)
                            && !WSSConstants.NS_XMLDSIG_FILTER2.equals(algorithm)
                            && !WSSConstants.SOAPMESSAGE_NS10_STRTransform.equals(algorithm)
                            && !WSSConstants.NS_XMLDSIG_ENVELOPED_SIGNATURE.equals(algorithm)
                            && !WSSConstants.SWA_ATTACHMENT_CONTENT_SIG_TRANS.equals(algorithm)
                            && !WSSConstants.SWA_ATTACHMENT_COMPLETE_SIG_TRANS.equals(algorithm)) {
                        securityContext.handleBSPRule(BSPRule.R5423);
                        if (j == transformTypes.size() - 1 &&
                            !WSSConstants.NS_C14N_EXCL.equals(algorithm)
                                && !WSSConstants.SOAPMESSAGE_NS10_STRTransform.equals(algorithm)
                                && !WSSConstants.SWA_ATTACHMENT_CONTENT_SIG_TRANS.equals(algorithm)
                                && !WSSConstants.SWA_ATTACHMENT_COMPLETE_SIG_TRANS.equals(algorithm)) {
                            securityContext.handleBSPRule(BSPRule.R5412);
                        }
                        InclusiveNamespaces inclusiveNamespacesType = XMLSecurityUtils.getQNameType(transformType.getContent(), XMLSecurityConstants.TAG_c14nExcl_InclusiveNamespaces);
                        if (WSSConstants.NS_C14N_EXCL.equals(algorithm)
                                && inclusiveNamespacesType != null
                                && inclusiveNamespacesType.getPrefixList().size() == 0) {
                            securityContext.handleBSPRule(BSPRule.R5407);
                        }
                        if (WSSConstants.SOAPMESSAGE_NS10_STRTransform.equals(algorithm)) {
                            if (inclusiveNamespacesType != null
                                    && inclusiveNamespacesType.getPrefixList().size() == 0) {
                                securityContext.handleBSPRule(BSPRule.R5413);
                            }
                            TransformationParametersType transformationParametersType =
                                    XMLSecurityUtils.getQNameType(transformType.getContent(), WSSConstants.TAG_wsse_TransformationParameters);
                            if (transformationParametersType == null) {
                                securityContext.handleBSPRule(BSPRule.R3065);
                            } else {
                                CanonicalizationMethodType canonicalizationMethodType =
                                        XMLSecurityUtils.getQNameType(transformationParametersType.getAny(), WSSConstants.TAG_dsig_CanonicalizationMethod);
                                if (canonicalizationMethodType == null) {
                                    securityContext.handleBSPRule(BSPRule.R3065);
                                }
                            }
                        }
                    }
                }
            }
            if (!WSSConstants.NS_XMLDSIG_SHA1.equals(referenceType.getDigestMethod().getAlgorithm())) {
                securityContext.handleBSPRule(BSPRule.R5420);
            }
        }
    }

    @Override
    public XMLSecEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {

        //this is the earliest possible point to check for an replay attack
        if (!replayChecked) {
            replayChecked = true;
            detectReplayAttack(inputProcessorChain);
        }
        return super.processNextEvent(inputProcessorChain);
    }

    @Override
    protected void processElementPath(List<QName> elementPath, InputProcessorChain inputProcessorChain,
                                      XMLSecEvent xmlSecEvent, ReferenceType referenceType)
            throws XMLSecurityException {
        //fire a SecurityEvent:
        final DocumentContext documentContext = inputProcessorChain.getDocumentContext();
        if (elementPath.size() == 3 && WSSUtils.isInSOAPHeader(elementPath)
                || elementPath.size() == 2 && WSSUtils.isInSOAPBody(elementPath)) {
            SignedPartSecurityEvent signedPartSecurityEvent =
                    new SignedPartSecurityEvent(getInboundSecurityToken(), true, documentContext.getProtectionOrder());
            signedPartSecurityEvent.setElementPath(elementPath);
            signedPartSecurityEvent.setXmlSecEvent(xmlSecEvent);
            signedPartSecurityEvent.setCorrelationID(referenceType.getId());
            inputProcessorChain.getSecurityContext().registerSecurityEvent(signedPartSecurityEvent);
        } else {
            SignedElementSecurityEvent signedElementSecurityEvent =
                    new SignedElementSecurityEvent(getInboundSecurityToken(), true, documentContext.getProtectionOrder());
            signedElementSecurityEvent.setElementPath(elementPath);
            signedElementSecurityEvent.setXmlSecEvent(xmlSecEvent);
            signedElementSecurityEvent.setCorrelationID(referenceType.getId());
            inputProcessorChain.getSecurityContext().registerSecurityEvent(signedElementSecurityEvent);
        }
    }

    @Override
    protected InternalSignatureReferenceVerifier getSignatureReferenceVerifier(
            XMLSecurityProperties securityProperties, InputProcessorChain inputProcessorChain,
            ReferenceType referenceType, XMLSecStartElement startElement) throws XMLSecurityException {
        return new InternalSignatureReferenceVerifier((WSSSecurityProperties) securityProperties,
                inputProcessorChain, referenceType, startElement);
    }

    private void detectReplayAttack(InputProcessorChain inputProcessorChain) throws WSSecurityException {
        TimestampSecurityEvent timestampSecurityEvent =
                inputProcessorChain.getSecurityContext().get(WSSConstants.PROP_TIMESTAMP_SECURITYEVENT);
        ReplayCache replayCache = 
            ((WSSSecurityProperties)getSecurityProperties()).getTimestampReplayCache();
        if (timestampSecurityEvent != null && replayCache != null) {
            final String cacheKey = String.valueOf(
                    timestampSecurityEvent.getCreated().getTimeInMillis()) +
                    "" + Arrays.hashCode(getSignatureType().getSignatureValue().getValue());
            if (replayCache.contains(cacheKey)) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.MESSAGE_EXPIRED);
            }
            
            // Store the Timestamp/SignatureValue combination in the cache
            Calendar expiresCal = timestampSecurityEvent.getExpires();
            if (expiresCal != null) {
                Date rightNow = new Date();
                long currentTime = rightNow.getTime();
                long expiresTime = expiresCal.getTimeInMillis();
                replayCache.add(cacheKey, (expiresTime - currentTime) / 1000L);
            } else {
                replayCache.add(cacheKey);
            }
        }
    }

    @Override
    protected Transformer buildTransformerChain(
            ReferenceType referenceType, OutputStream outputStream,
            InputProcessorChain inputProcessorChain,
            AbstractSignatureReferenceVerifyInputProcessor.InternalSignatureReferenceVerifier internalSignatureReferenceVerifier)
            throws XMLSecurityException {

        if (referenceType.getTransforms() == null || referenceType.getTransforms().getTransform().size() == 0) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY);
        }
        List<TransformType> transformTypeList = referenceType.getTransforms().getTransform();

        if (transformTypeList.size() > maximumAllowedTransformsPerReference) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY,
                    "secureProcessing.MaximumAllowedTransformsPerReference",
                    transformTypeList.size(),
                    maximumAllowedTransformsPerReference);
        }

        String algorithm = null;
        Transformer parentTransformer = null;
        for (int i = transformTypeList.size() - 1; i >= 0; i--) {
            TransformType transformType = transformTypeList.get(i);
            TransformationParametersType transformationParametersType =
                    XMLSecurityUtils.getQNameType(transformType.getContent(), WSSConstants.TAG_wsse_TransformationParameters);
            if (transformationParametersType != null) {
                CanonicalizationMethodType canonicalizationMethodType =
                        XMLSecurityUtils.getQNameType(transformationParametersType.getAny(), WSSConstants.TAG_dsig_CanonicalizationMethod);
                if (canonicalizationMethodType != null) {

                    InclusiveNamespaces inclusiveNamespacesType =
                            XMLSecurityUtils.getQNameType(canonicalizationMethodType.getContent(), XMLSecurityConstants.TAG_c14nExcl_InclusiveNamespaces);
                    List<String> inclusiveNamespaces = inclusiveNamespacesType != null ? inclusiveNamespacesType.getPrefixList() : null;
                    algorithm = canonicalizationMethodType.getAlgorithm();
                    parentTransformer = WSSUtils.getTransformer(inclusiveNamespaces, outputStream, algorithm, XMLSecurityConstants.DIRECTION.IN);
                }
            }
            algorithm = transformType.getAlgorithm();
            AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent();
            algorithmSuiteSecurityEvent.setAlgorithmURI(algorithm);
            algorithmSuiteSecurityEvent.setAlgorithmUsage(WSSConstants.C14n);
            algorithmSuiteSecurityEvent.setCorrelationID(referenceType.getId());
            inputProcessorChain.getSecurityContext().registerSecurityEvent(algorithmSuiteSecurityEvent);

            InclusiveNamespaces inclusiveNamespacesType = XMLSecurityUtils.getQNameType(transformType.getContent(), XMLSecurityConstants.TAG_c14nExcl_InclusiveNamespaces);
            List<String> inclusiveNamespaces = inclusiveNamespacesType != null ? inclusiveNamespacesType.getPrefixList() : null;

            if (parentTransformer != null) {
                parentTransformer = WSSUtils.getTransformer(parentTransformer, inclusiveNamespaces, algorithm, XMLSecurityConstants.DIRECTION.IN);
            } else {
                parentTransformer = WSSUtils.getTransformer(inclusiveNamespaces, outputStream, algorithm, XMLSecurityConstants.DIRECTION.IN);
            }
        }

        if (WSSConstants.SOAPMESSAGE_NS10_STRTransform.equals(algorithm)) {

            internalSignatureReferenceVerifier.setTransformer(parentTransformer);

            SecurityTokenProvider<? extends InboundSecurityToken> securityTokenProvider =
                    inputProcessorChain.getSecurityContext().getSecurityTokenProvider(XMLSecurityUtils.dropReferenceMarker(referenceType.getURI()));
            if (securityTokenProvider == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "noReference");
            }
            SecurityToken securityToken = securityTokenProvider.getSecurityToken();
            if (!(securityToken instanceof SecurityTokenReference)) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.UNSUPPORTED_SECURITY_TOKEN);
            }
            SecurityTokenReference securityTokenReference = (SecurityTokenReference) securityToken;
            //todo analyse and fix me: the following statement could be problematic
            inputProcessorChain.getDocumentContext().setIsInSignedContent(inputProcessorChain.getProcessors().indexOf(internalSignatureReferenceVerifier), internalSignatureReferenceVerifier);
            XMLSecStartElement xmlSecStartElement = securityTokenReference.getXmlSecEvents().getLast().asStartElement();
            internalSignatureReferenceVerifier.setStartElement(xmlSecStartElement);
            Iterator<XMLSecEvent> xmlSecEventIterator = securityTokenReference.getXmlSecEvents().descendingIterator();
            try {
                while (xmlSecEventIterator.hasNext()) {
                    internalSignatureReferenceVerifier.processEvent(xmlSecEventIterator.next(), inputProcessorChain);
                }
            } catch (XMLStreamException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
            }
        }
        return parentTransformer;
    }

    class InternalSignatureReferenceVerifier extends AbstractSignatureReferenceVerifyInputProcessor.InternalSignatureReferenceVerifier {

        InternalSignatureReferenceVerifier(WSSSecurityProperties securityProperties, InputProcessorChain inputProcessorChain,
                                           ReferenceType referenceType, XMLSecStartElement startElement) throws XMLSecurityException {
            super(securityProperties, inputProcessorChain, referenceType, startElement);
            this.addAfterProcessor(WSSSignatureReferenceVerifyInputProcessor.class.getName());
        }
    }
}
