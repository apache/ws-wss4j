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
import org.swssf.binding.excc14n.InclusiveNamespaces;
import org.swssf.binding.wss10.TransformationParametersType;
import org.swssf.binding.xmldsig.CanonicalizationMethodType;
import org.swssf.binding.xmldsig.ReferenceType;
import org.swssf.binding.xmldsig.SignatureType;
import org.swssf.binding.xmldsig.TransformType;
import org.swssf.wss.ext.*;
import org.swssf.wss.impl.securityToken.SecurityTokenReference;
import org.swssf.wss.securityEvent.AlgorithmSuiteSecurityEvent;
import org.swssf.wss.securityEvent.SignedElementSecurityEvent;
import org.swssf.wss.securityEvent.SignedPartSecurityEvent;
import org.swssf.wss.securityEvent.TimestampSecurityEvent;
import org.swssf.xmlsec.ext.*;
import org.swssf.xmlsec.impl.processor.input.AbstractSignatureReferenceVerifyInputProcessor;
import org.xmlsecurity.ns.configuration.AlgorithmType;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Arrays;
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

    public SignatureReferenceVerifyInputProcessor(
            SignatureType signatureType, SecurityToken securityToken,
            XMLSecurityProperties securityProperties, WSSecurityContext securityContext) throws XMLSecurityException {
        super(signatureType, securityToken, securityProperties);
        this.addAfterProcessor(SignatureReferenceVerifyInputProcessor.class.getName());

        checkBSPCompliance(securityContext);
    }

    private void checkBSPCompliance(WSSecurityContext securityContext) throws WSSecurityException {
        List<ReferenceType> references = getSignatureType().getSignedInfo().getReference();
        for (int i = 0; i < references.size(); i++) {
            ReferenceType referenceType = references.get(i);
            if (referenceType.getTransforms() == null) {
                securityContext.handleBSPRule(WSSConstants.BSPRule.R5416);
            } else if (referenceType.getTransforms().getTransform().size() == 0) {
                securityContext.handleBSPRule(WSSConstants.BSPRule.R5411);
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
                        securityContext.handleBSPRule(WSSConstants.BSPRule.R5423);
                        if (j == transformTypes.size() - 1) {
                            if (!WSSConstants.NS_C14N_EXCL.equals(algorithm)
                                    && !WSSConstants.SOAPMESSAGE_NS10_STRTransform.equals(algorithm)
                                    && !WSSConstants.SWA_ATTACHMENT_CONTENT_SIG_TRANS.equals(algorithm)
                                    && !WSSConstants.SWA_ATTACHMENT_COMPLETE_SIG_TRANS.equals(algorithm)) {
                                securityContext.handleBSPRule(WSSConstants.BSPRule.R5412);
                            }
                        }
                        InclusiveNamespaces inclusiveNamespacesType = XMLSecurityUtils.getQNameType(transformType.getContent(), XMLSecurityConstants.TAG_c14nExcl_InclusiveNamespaces);
                        if (WSSConstants.NS_C14N_EXCL.equals(algorithm)
                                && inclusiveNamespacesType != null
                                && inclusiveNamespacesType.getPrefixList().size() == 0) {
                            securityContext.handleBSPRule(WSSConstants.BSPRule.R5407);
                        }
                        if (WSSConstants.SOAPMESSAGE_NS10_STRTransform.equals(algorithm)) {
                            if (inclusiveNamespacesType != null
                                    && inclusiveNamespacesType.getPrefixList().size() == 0) {
                                securityContext.handleBSPRule(WSSConstants.BSPRule.R5413);
                            }
                            TransformationParametersType transformationParametersType =
                                    XMLSecurityUtils.getQNameType(transformType.getContent(), WSSConstants.TAG_wsse_TransformationParameters);
                            if (transformationParametersType == null) {
                                securityContext.handleBSPRule(WSSConstants.BSPRule.R3065);
                            } else {
                                CanonicalizationMethodType canonicalizationMethodType =
                                        XMLSecurityUtils.getQNameType(transformationParametersType.getAny(), WSSConstants.TAG_dsig_CanonicalizationMethod);
                                if (canonicalizationMethodType == null) {
                                    securityContext.handleBSPRule(WSSConstants.BSPRule.R3065);
                                }
                            }
                        }
                    }
                }
            }
            if (!WSSConstants.NS_XMLDSIG_SHA1.equals(referenceType.getDigestMethod().getAlgorithm())) {
                securityContext.handleBSPRule(WSSConstants.BSPRule.R5420);
            }
        }
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
            final WSSDocumentContext documentContext = (WSSDocumentContext) inputProcessorChain.getDocumentContext();
            StartElement startElement = xmlEvent.asStartElement();
            ReferenceType referenceType = matchesReferenceId(startElement);
            if (referenceType != null) {

                if (getProcessedReferences().contains(referenceType)) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, "duplicateId");
                }
                InternalSignatureReferenceVerifier internalSignatureReferenceVerifier =
                        new InternalSignatureReferenceVerifier(
                                ((WSSSecurityProperties) getSecurityProperties()), inputProcessorChain,
                                referenceType, startElement.getName());
                if (!internalSignatureReferenceVerifier.isFinished()) {
                    internalSignatureReferenceVerifier.processEvent(xmlEvent, inputProcessorChain);
                    inputProcessorChain.addProcessor(internalSignatureReferenceVerifier);
                }
                getProcessedReferences().add(referenceType);
                documentContext.setIsInSignedContent(inputProcessorChain.getProcessors().indexOf(internalSignatureReferenceVerifier), internalSignatureReferenceVerifier);

                //fire a SecurityEvent:
                if (documentContext.getDocumentLevel() == 3
                        && documentContext.isInSOAPHeader()) {
                    SignedPartSecurityEvent signedPartSecurityEvent =
                            new SignedPartSecurityEvent(getSecurityToken(), true, documentContext.getProtectionOrder());
                    signedPartSecurityEvent.setElementPath(documentContext.getPath());
                    signedPartSecurityEvent.setXmlEvent(xmlEvent);
                    ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(signedPartSecurityEvent);
                } else {
                    SignedElementSecurityEvent signedElementSecurityEvent =
                            new SignedElementSecurityEvent(getSecurityToken(), true, documentContext.getProtectionOrder());
                    signedElementSecurityEvent.setElementPath(documentContext.getPath());
                    signedElementSecurityEvent.setXmlEvent(xmlEvent);
                    ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(signedElementSecurityEvent);
                }
            }
        }
        return xmlEvent;
    }

    private void detectReplayAttack(InputProcessorChain inputProcessorChain) throws WSSecurityException {
        TimestampSecurityEvent timestampSecurityEvent = inputProcessorChain.getSecurityContext().get(WSSConstants.PROP_TIMESTAMP_SECURITYEVENT);
        if (timestampSecurityEvent != null) {
            final String cacheKey = String.valueOf(
                    timestampSecurityEvent.getCreated().getTimeInMillis()) +
                    "" + Arrays.hashCode(getSignatureType().getSignatureValue().getValue());
            if (cache.get(cacheKey) != null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.MESSAGE_EXPIRED);
            }
            ElementAttributes elementAttributes = new ElementAttributes();
            if (timestampSecurityEvent.getExpires() != null) {
                long lifeTime = timestampSecurityEvent.getExpires().getTimeInMillis() - System.currentTimeMillis();
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

        InternalSignatureReferenceVerifier(WSSSecurityProperties securityProperties, InputProcessorChain inputProcessorChain,
                                           ReferenceType referenceType, QName startElement) throws XMLSecurityException {
            super(securityProperties, inputProcessorChain, referenceType, startElement);
            this.addAfterProcessor(SignatureReferenceVerifyInputProcessor.class.getName());
        }

        protected AlgorithmType createMessageDigest(SecurityContext securityContext)
                throws XMLSecurityException, NoSuchAlgorithmException, NoSuchProviderException {
            AlgorithmType digestAlgorithm = super.createMessageDigest(securityContext);

            AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent();
            algorithmSuiteSecurityEvent.setAlgorithmURI(digestAlgorithm.getURI());
            algorithmSuiteSecurityEvent.setKeyUsage(WSSConstants.Dig);
            ((WSSecurityContext) securityContext).registerSecurityEvent(algorithmSuiteSecurityEvent);
            return digestAlgorithm;
        }

        protected void buildTransformerChain(ReferenceType referenceType, InputProcessorChain inputProcessorChain)
                throws XMLSecurityException, XMLStreamException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {

            if (referenceType.getTransforms() == null || referenceType.getTransforms().getTransform().size() == 0) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK);
            }
            List<TransformType> transformTypeList = referenceType.getTransforms().getTransform();

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
                        if (WSSConstants.SOAPMESSAGE_NS10_STRTransform.equals(transformType.getAlgorithm())) {
                            if (inclusiveNamespaces == null) {
                                inclusiveNamespaces = new ArrayList<String>(1);
                            }
                            inclusiveNamespaces.add("#default");
                        }
                        algorithm = canonicalizationMethodType.getAlgorithm();
                        parentTransformer = WSSUtils.getTransformer(inclusiveNamespaces, this.getBufferedDigestOutputStream(), algorithm);
                    }
                }
                algorithm = transformType.getAlgorithm();
                AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent();
                algorithmSuiteSecurityEvent.setAlgorithmURI(algorithm);
                algorithmSuiteSecurityEvent.setKeyUsage(WSSConstants.C14n);
                ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(algorithmSuiteSecurityEvent);

                InclusiveNamespaces inclusiveNamespacesType = XMLSecurityUtils.getQNameType(transformType.getContent(), XMLSecurityConstants.TAG_c14nExcl_InclusiveNamespaces);
                List<String> inclusiveNamespaces = inclusiveNamespacesType != null ? inclusiveNamespacesType.getPrefixList() : null;

                if (parentTransformer != null) {
                    parentTransformer = WSSUtils.getTransformer(parentTransformer, inclusiveNamespaces, algorithm);
                } else {
                    parentTransformer = WSSUtils.getTransformer(inclusiveNamespaces, this.getBufferedDigestOutputStream(), algorithm);
                }
            }

            this.setTransformer(parentTransformer);

            if (WSSConstants.SOAPMESSAGE_NS10_STRTransform.equals(algorithm)) {
                SecurityTokenProvider securityTokenProvider = inputProcessorChain.getSecurityContext().getSecurityTokenProvider(XMLSecurityUtils.dropReferenceMarker(referenceType.getURI()));
                if (securityTokenProvider == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "noReference");
                }
                SecurityToken securityToken = securityTokenProvider.getSecurityToken();
                if (!(securityToken instanceof SecurityTokenReference)) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.UNSUPPORTED_SECURITY_TOKEN);
                }
                SecurityTokenReference securityTokenReference = (SecurityTokenReference) securityToken;
                //todo analyse and fix me: the following statement could be problematic
                inputProcessorChain.getDocumentContext().setIsInSignedContent(inputProcessorChain.getProcessors().indexOf(this), this);
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
