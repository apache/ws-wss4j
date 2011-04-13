/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.impl.processor.input;

import org.apache.commons.codec.binary.Base64;
import org.swssf.config.JCEAlgorithmMapper;
import org.swssf.config.TransformerAlgorithmMapper;
import org.swssf.ext.*;
import org.swssf.impl.transformer.canonicalizer.Canonicalizer20010315Transformer;
import org.swssf.impl.util.DigestOutputStream;
import org.swssf.securityEvent.SecurityEvent;
import org.swssf.securityEvent.SignedElementSecurityEvent;
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
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class SignatureReferenceVerifyInputProcessor extends AbstractInputProcessor {

    private SignatureType signatureType;

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
                            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, "duplicateId");
                        }
                        InternalSignatureReferenceVerifier internalSignatureReferenceVerifier =
                                new InternalSignatureReferenceVerifier(getSecurityProperties(), referenceType, startElement.getName());
                        internalSignatureReferenceVerifier.processEvent(xmlEvent, inputProcessorChain);
                        inputProcessorChain.addProcessor(internalSignatureReferenceVerifier);
                        referenceType.setProcessed(true);
                        inputProcessorChain.getDocumentContext().setIsInSignedContent();

                        //fire a SecurityEvent:
                        //if (level == 2 && isInSoapHeader) {//todo this is not correct. It is only a header event when we are at top level in the soap header
                        //todo an encrypted top-level soap-header element counts as EncryptedPartSecurityEvent
                        //todo these if-else statements here must be designed with care
                        //todo we need the infrastructure to detect where we are in the document.
                        //todo This can be useful below to handle encrypted header elements like timestamps
                        //todo and also for policy verification elsewhere
                        //SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(SecurityEvent.Event.SignedPart);
                        //signedPartSecurityEvent.setElement(startElement.getName());
                        //securityContext.registerSecurityEvent(signedPartSecurityEvent);
                        //} else {                            
                        SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(SecurityEvent.Event.SignedElement, false);
                        signedElementSecurityEvent.setElement(startElement.getName());
                        inputProcessorChain.getSecurityContext().registerSecurityEvent(signedElementSecurityEvent);
                        //}
                    }
                }
            }
        }

        return xmlEvent;
    }

    @Override
    public void doFinal(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
        List<ReferenceType> references = signatureType.getSignedInfo().getReference();
        for (int i = 0; i < references.size(); i++) {
            ReferenceType referenceType = references.get(i);
            if (!referenceType.isProcessed()) {
                throw new WSSecurityException(WSSecurityException.FAILED_CHECK, "unprocessedSignatureReferences");
            }
        }
        inputProcessorChain.doFinal();
    }

    class InternalSignatureReferenceVerifier extends AbstractInputProcessor {
        private ReferenceType referenceType;

        private List<Transformer> transformers = new LinkedList<Transformer>();
        private DigestOutputStream digestOutputStream;
        private OutputStream bufferedDigestOutputStream;
        //todo: startElement still needed?? Is elementCounter not enough? Test overall code
        private QName startElement;
        private int elementCounter = 0;

        public InternalSignatureReferenceVerifier(SecurityProperties securityProperties, ReferenceType referenceType, QName startElement) throws WSSecurityException {
            super(securityProperties);
            this.getAfterProcessors().add(SignatureReferenceVerifyInputProcessor.class.getName());
            this.startElement = startElement;
            this.referenceType = referenceType;
            try {
                createMessageDigest();
                buildTransformerChain(referenceType);
            } catch (Exception e) {
                throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, e);
            }
        }

        private void createMessageDigest() throws NoSuchAlgorithmException, NoSuchProviderException {
            AlgorithmType digestAlgorithm = JCEAlgorithmMapper.getAlgorithmMapping(referenceType.getDigestMethod().getAlgorithm());
            MessageDigest messageDigest = MessageDigest.getInstance(digestAlgorithm.getJCEName(), digestAlgorithm.getJCEProvider());
            this.digestOutputStream = new DigestOutputStream(messageDigest);
            this.bufferedDigestOutputStream = new BufferedOutputStream(this.digestOutputStream);
        }

        private void buildTransformerChain(ReferenceType referenceType) throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
            List<TransformType> transformTypeList = referenceType.getTransforms().getTransform();
            for (int i = 0; i < transformTypeList.size(); i++) {
                TransformType transformType = transformTypeList.get(i);

                Class<Transformer> transformerClass = TransformerAlgorithmMapper.getTransformerClass(transformType.getAlgorithm());
                Transformer transformer;
                if (Canonicalizer20010315Transformer.class.isAssignableFrom(transformerClass)) {
                    Constructor<Transformer> constructor = transformerClass.getConstructor(String.class);
                    transformer = constructor.newInstance((String) null);
                } else {
                    transformer = transformerClass.newInstance();
                }
                transformers.add(transformer);
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
            Iterator<Transformer> transformerIterator = transformers.iterator();
            while (transformerIterator.hasNext()) {
                Transformer transformer = transformerIterator.next();
                transformer.transform(xmlEvent, this.bufferedDigestOutputStream);
            }

            if (xmlEvent.isStartElement()) {
                elementCounter++;
            } else if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                elementCounter--;

                if (endElement.getName().equals(startElement) && elementCounter == 0) {
                    try {
                        bufferedDigestOutputStream.close();
                    } catch (IOException e) {
                        throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, e);
                    }

                    byte[] calculatedDigest = this.digestOutputStream.getDigestValue();
                    byte[] storedDigest = Base64.decodeBase64(referenceType.getDigestValue());

                    if (logger.isDebugEnabled()) {
                        logger.debug("Calculated Digest: " + new String(Base64.encodeBase64(calculatedDigest)));
                        logger.debug("Stored Digest: " + new String(Base64.encodeBase64(storedDigest)));
                    }

                    if (!MessageDigest.isEqual(storedDigest, calculatedDigest)) {
                        throw new WSSecurityException(WSSecurityException.FAILED_CHECK, "digestVerificationFailed");
                    }
                    inputProcessorChain.removeProcessor(this);
                    inputProcessorChain.getDocumentContext().unsetIsInSignedContent();
                }
            }
        }
    }
}
