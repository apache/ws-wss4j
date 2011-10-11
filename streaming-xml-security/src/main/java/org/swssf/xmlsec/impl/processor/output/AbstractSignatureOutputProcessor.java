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
package org.swssf.xmlsec.impl.processor.output;

import org.apache.commons.codec.binary.Base64;
import org.swssf.xmlsec.config.JCEAlgorithmMapper;
import org.swssf.xmlsec.ext.*;
import org.swssf.xmlsec.impl.SignaturePartDef;
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
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public abstract class AbstractSignatureOutputProcessor extends AbstractOutputProcessor {

    private List<SecurePart> secureParts;
    private List<SignaturePartDef> signaturePartDefList = new LinkedList<SignaturePartDef>();

    private InternalSignatureOutputProcessor activeInternalSignatureOutputProcessor = null;

    public AbstractSignatureOutputProcessor(XMLSecurityProperties securityProperties, XMLSecurityConstants.Action action) throws XMLSecurityException {
        super(securityProperties, action);
        secureParts = securityProperties.getSignatureSecureParts();
    }

    public List<SignaturePartDef> getSignaturePartDefList() {
        return signaturePartDefList;
    }

    @Override
    public abstract void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException;


    protected SecurePart securePartMatches(StartElement startElement, OutputProcessorChain outputProcessorChain) {
        SecurePart securePart = securePartMatches(startElement, this.secureParts);
        if (securePart != null) {
            return securePart;
        }
        List<SecurePart> secureParts = outputProcessorChain.getSecurityContext().getAsList(SecurePart.class);
        if (secureParts == null) {
            return null;
        }
        return securePartMatches(startElement, secureParts);
    }

    protected SecurePart securePartMatches(StartElement startElement, List<SecurePart> secureParts) {
        Iterator<SecurePart> securePartIterator = secureParts.iterator();
        while (securePartIterator.hasNext()) {
            SecurePart securePart = securePartIterator.next();
            if (securePart.getIdToSign() == null) {
                if (startElement.getName().getLocalPart().equals(securePart.getName())
                        && startElement.getName().getNamespaceURI().equals(securePart.getNamespace())) {
                    return securePart;
                }
            } else {
                @SuppressWarnings("unchecked")
                Iterator<Attribute> attributeIterator = startElement.getAttributes();
                while (attributeIterator.hasNext()) {
                    Attribute attribute = attributeIterator.next();
                    if (attribute != null) {
                        QName attributeName = attribute.getName();
                        if ((attributeName.equals(XMLSecurityConstants.ATT_NULL_Id))
                                && attribute.getValue().equals(securePart.getIdToSign())) {
                            return securePart;
                        }
                    }
                }
            }
        }
        return null;
    }

    protected InternalSignatureOutputProcessor getActiveInternalSignatureOutputProcessor() {
        return activeInternalSignatureOutputProcessor;
    }

    protected void setActiveInternalSignatureOutputProcessor(InternalSignatureOutputProcessor activeInternalSignatureOutputProcessor) {
        this.activeInternalSignatureOutputProcessor = activeInternalSignatureOutputProcessor;
    }

    public class InternalSignatureOutputProcessor extends AbstractOutputProcessor {

        private SignaturePartDef signaturePartDef;
        private QName startElement;
        private int elementCounter = 0;

        private OutputStream bufferedDigestOutputStream;
        private DigestOutputStream digestOutputStream;
        private Transformer transformer;

        public InternalSignatureOutputProcessor(XMLSecurityProperties securityProperties, XMLSecurityConstants.Action action, SignaturePartDef signaturePartDef, QName startElement) throws XMLSecurityException, NoSuchProviderException, NoSuchAlgorithmException {
            super(securityProperties, action);
            this.getBeforeProcessors().add(InternalSignatureOutputProcessor.class.getName());
            this.signaturePartDef = signaturePartDef;
            this.startElement = startElement;

            AlgorithmType algorithmID = JCEAlgorithmMapper.getAlgorithmMapping(getSecurityProperties().getSignatureDigestAlgorithm());
            MessageDigest messageDigest = MessageDigest.getInstance(algorithmID.getJCEName(), algorithmID.getJCEProvider());
            this.digestOutputStream = new DigestOutputStream(messageDigest);
            this.bufferedDigestOutputStream = new BufferedOutputStream(digestOutputStream);

            try {
                if (signaturePartDef.getTransformAlgo() != null) {
                    Transformer transformer = XMLSecurityUtils.getTransformer("#default", this.bufferedDigestOutputStream, signaturePartDef.getC14nAlgo());
                    this.transformer = XMLSecurityUtils.getTransformer(transformer, null, signaturePartDef.getTransformAlgo());
                } else {
                    transformer = XMLSecurityUtils.getTransformer(null, this.bufferedDigestOutputStream, signaturePartDef.getC14nAlgo());
                }
            } catch (NoSuchMethodException e) {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
            } catch (InstantiationException e) {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
            } catch (IllegalAccessException e) {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
            } catch (InvocationTargetException e) {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
            }
        }

        @Override
        public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {

            transformer.transform(xmlEvent);

            if (xmlEvent.isStartElement()) {
                elementCounter++;
            } else if (xmlEvent.isEndElement()) {
                elementCounter--;

                EndElement endElement = xmlEvent.asEndElement();

                if (endElement.getName().equals(this.startElement) && elementCounter == 0) {
                    try {
                        bufferedDigestOutputStream.close();
                    } catch (IOException e) {
                        throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
                    }
                    String calculatedDigest = new String(Base64.encodeBase64(this.digestOutputStream.getDigestValue()));
                    logger.debug("Calculated Digest: " + calculatedDigest);
                    signaturePartDef.setDigestValue(calculatedDigest);

                    outputProcessorChain.removeProcessor(this);
                    //from now on signature is possible again
                    setActiveInternalSignatureOutputProcessor(null);
                    xmlEvent = createEndElement(startElement);
                }
            }
            outputProcessorChain.processEvent(xmlEvent);
        }
    }
}
