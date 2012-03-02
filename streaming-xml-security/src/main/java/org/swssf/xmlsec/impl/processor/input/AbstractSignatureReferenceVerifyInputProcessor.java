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
package org.swssf.xmlsec.impl.processor.input;

import org.apache.commons.codec.binary.Base64;
import org.swssf.binding.excc14n.InclusiveNamespaces;
import org.swssf.binding.xmldsig.ReferenceType;
import org.swssf.binding.xmldsig.SignatureType;
import org.swssf.binding.xmldsig.TransformType;
import org.swssf.xmlsec.config.JCEAlgorithmMapper;
import org.swssf.xmlsec.ext.*;
import org.swssf.xmlsec.impl.util.DigestOutputStream;
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
import java.util.ArrayList;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public abstract class AbstractSignatureReferenceVerifyInputProcessor extends AbstractInputProcessor {

    private SignatureType signatureType;
    private SecurityToken securityToken;
    private List<ReferenceType> processedReferences = new ArrayList<ReferenceType>();

    public AbstractSignatureReferenceVerifyInputProcessor(SignatureType signatureType, SecurityToken securityToken, XMLSecurityProperties securityProperties) {
        super(securityProperties);
        this.signatureType = signatureType;
        this.securityToken = securityToken;
    }

    public SignatureType getSignatureType() {
        return signatureType;
    }

    public List<ReferenceType> getProcessedReferences() {
        return processedReferences;
    }

    public SecurityToken getSecurityToken() {
        return securityToken;
    }

    @Override
    public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        return inputProcessorChain.processHeaderEvent();
    }

    @Override
    public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {

        XMLEvent xmlEvent = inputProcessorChain.processEvent();

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();
            ReferenceType referenceType = matchesReferenceId(startElement);
            if (referenceType != null) {

                if (processedReferences.contains(referenceType)) {
                    throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_CHECK, "duplicateId");
                }
                InternalSignatureReferenceVerifier internalSignatureReferenceVerifier =
                        new InternalSignatureReferenceVerifier(getSecurityProperties(), inputProcessorChain, referenceType, startElement.getName());
                if (!internalSignatureReferenceVerifier.isFinished()) {
                    internalSignatureReferenceVerifier.processEvent(xmlEvent, inputProcessorChain);
                    inputProcessorChain.addProcessor(internalSignatureReferenceVerifier);
                }
                processedReferences.add(referenceType);
                inputProcessorChain.getDocumentContext().setIsInSignedContent(
                        inputProcessorChain.getProcessors().indexOf(internalSignatureReferenceVerifier), internalSignatureReferenceVerifier);
            }
        }
        return xmlEvent;
    }

    protected ReferenceType matchesReferenceId(StartElement startElement) {
        Attribute refId = getReferenceIDAttribute(startElement);
        if (refId != null) {
            List<ReferenceType> references = getSignatureType().getSignedInfo().getReference();
            for (int i = 0; i < references.size(); i++) {
                ReferenceType referenceType = references.get(i);
                if (refId.getValue().equals(XMLSecurityUtils.dropReferenceMarker(referenceType.getURI()))) {
                    logger.debug("Found signature reference: " + refId.getValue() + " on element" + startElement.getName());
                    return referenceType;
                }
            }
        }
        return null;
    }

    @Override
    public void doFinal(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        List<ReferenceType> references = getSignatureType().getSignedInfo().getReference();
        for (int i = 0; i < references.size(); i++) {
            ReferenceType referenceType = references.get(i);
            if (!processedReferences.contains(referenceType)) {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_CHECK, "unprocessedSignatureReferences");
            }
        }
        inputProcessorChain.doFinal();
    }

    public class InternalSignatureReferenceVerifier extends AbstractInputProcessor {
        private ReferenceType referenceType;
        private Transformer transformer;
        private DigestOutputStream digestOutputStream;
        private OutputStream bufferedDigestOutputStream;
        private QName startElement;
        private int elementCounter = 0;
        private boolean finished = false;

        public InternalSignatureReferenceVerifier(
                XMLSecurityProperties securityProperties, InputProcessorChain inputProcessorChain,
                ReferenceType referenceType, QName startElement) throws XMLSecurityException {

            super(securityProperties);
            this.setStartElement(startElement);
            this.setReferenceType(referenceType);
            try {
                createMessageDigest(inputProcessorChain.getSecurityContext());
                buildTransformerChain(referenceType, inputProcessorChain);
            } catch (Exception e) {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_CHECK, e);
            }
        }

        protected AlgorithmType createMessageDigest(SecurityContext securityContext) throws XMLSecurityException, NoSuchAlgorithmException, NoSuchProviderException {
            AlgorithmType digestAlgorithm = JCEAlgorithmMapper.getAlgorithmMapping(getReferenceType().getDigestMethod().getAlgorithm());

            MessageDigest messageDigest = MessageDigest.getInstance(digestAlgorithm.getJCEName(), digestAlgorithm.getJCEProvider());
            this.setDigestOutputStream(new DigestOutputStream(messageDigest));
            this.setBufferedDigestOutputStream(new BufferedOutputStream(this.getDigestOutputStream()));
            return digestAlgorithm;
        }

        protected void buildTransformerChain(ReferenceType referenceType, InputProcessorChain inputProcessorChain) throws XMLSecurityException, XMLStreamException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
            List<TransformType> transformTypeList = referenceType.getTransforms().getTransform();

            Transformer parentTransformer = null;
            for (int i = transformTypeList.size() - 1; i >= 0; i--) {
                TransformType transformType = transformTypeList.get(i);

                InclusiveNamespaces inclusiveNamespacesType = XMLSecurityUtils.getQNameType(transformType.getContent(), XMLSecurityConstants.TAG_c14nExcl_InclusiveNamespaces);
                List<String> inclusiveNamespaces = inclusiveNamespacesType != null ? inclusiveNamespacesType.getPrefixList() : null;
                String algorithm = transformType.getAlgorithm();
                if (parentTransformer != null) {
                    parentTransformer = XMLSecurityUtils.getTransformer(parentTransformer, inclusiveNamespaces, algorithm);
                } else {
                    parentTransformer = XMLSecurityUtils.getTransformer(inclusiveNamespaces, this.getBufferedDigestOutputStream(), algorithm);
                }
            }
            this.setTransformer(parentTransformer);
        }

        @Override
        public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
            return inputProcessorChain.processHeaderEvent();
        }

        @Override
        public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
            XMLEvent xmlEvent = inputProcessorChain.processEvent();
            processEvent(xmlEvent, inputProcessorChain);
            return xmlEvent;
        }

        protected void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {

            getTransformer().transform(xmlEvent);

            if (xmlEvent.isStartElement()) {
                setElementCounter(getElementCounter() + 1);
            } else if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                setElementCounter(getElementCounter() - 1);

                if (endElement.getName().equals(getStartElement()) && getElementCounter() == 0) {
                    try {
                        getBufferedDigestOutputStream().close();
                    } catch (IOException e) {
                        throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_CHECK, e);
                    }

                    byte[] calculatedDigest = this.getDigestOutputStream().getDigestValue();
                    byte[] storedDigest = getReferenceType().getDigestValue();

                    if (logger.isDebugEnabled()) {
                        logger.debug("Calculated Digest: " + new String(Base64.encodeBase64(calculatedDigest)));
                        logger.debug("Stored Digest: " + new String(Base64.encodeBase64(storedDigest)));
                    }

                    if (!MessageDigest.isEqual(storedDigest, calculatedDigest)) {
                        throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_CHECK, "digestVerificationFailed", getReferenceType().getURI());
                    }
                    inputProcessorChain.removeProcessor(this);
                    inputProcessorChain.getDocumentContext().unsetIsInSignedContent(this);
                    setFinished(true);
                }
            }
        }

        public boolean isFinished() {
            return finished;
        }

        protected ReferenceType getReferenceType() {
            return referenceType;
        }

        protected void setReferenceType(ReferenceType referenceType) {
            this.referenceType = referenceType;
        }

        protected Transformer getTransformer() {
            return transformer;
        }

        protected void setTransformer(Transformer transformer) {
            this.transformer = transformer;
        }

        protected DigestOutputStream getDigestOutputStream() {
            return digestOutputStream;
        }

        protected void setDigestOutputStream(DigestOutputStream digestOutputStream) {
            this.digestOutputStream = digestOutputStream;
        }

        protected OutputStream getBufferedDigestOutputStream() {
            return bufferedDigestOutputStream;
        }

        protected void setBufferedDigestOutputStream(OutputStream bufferedDigestOutputStream) {
            this.bufferedDigestOutputStream = bufferedDigestOutputStream;
        }

        protected QName getStartElement() {
            return startElement;
        }

        protected void setStartElement(QName startElement) {
            this.startElement = startElement;
        }

        protected int getElementCounter() {
            return elementCounter;
        }

        protected void setElementCounter(int elementCounter) {
            this.elementCounter = elementCounter;
        }

        protected void setFinished(boolean finished) {
            this.finished = finished;
        }
    }
}
