package ch.gigerstyle.xmlsec.impl.processor.input;

import ch.gigerstyle.xmlsec.config.JCEAlgorithmMapper;
import ch.gigerstyle.xmlsec.ext.*;
import ch.gigerstyle.xmlsec.impl.transformer.canonicalizer.Canonicalizer20010315ExclOmitCommentsTransformer;
import ch.gigerstyle.xmlsec.impl.util.DigestOutputStream;
import ch.gigerstyle.xmlsec.securityEvent.SecurityEvent;
import ch.gigerstyle.xmlsec.securityEvent.SignedElementSecurityEvent;
import org.w3._2000._09.xmldsig_.ReferenceType;
import org.w3._2000._09.xmldsig_.SignatureType;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.List;

/**
 * User: giger
 * Date: May 14, 2010
 * Time: 2:36:01 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class SignatureReferenceVerifyInputProcessor extends AbstractInputProcessor {

    private SignatureType signatureType;

    public SignatureReferenceVerifyInputProcessor(SignatureType signatureType, SecurityProperties securityProperties) {
        super(securityProperties);
        this.signatureType = signatureType;
        this.getAfterProcessors().add(SignatureInputProcessor.class.getName());
        this.getAfterProcessors().add(SignatureReferenceVerifyInputProcessor.class.getName());
    }

    @Override
    public void processSecurityHeaderEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        inputProcessorChain.processSecurityHeaderEvent(xmlEvent);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
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
                            throw new XMLSecurityException("duplicate id encountered!");
                        }
                        inputProcessorChain.addProcessor(new InternalSignatureReferenceVerifier(getSecurityProperties(), referenceType, startElement.getName()));
                        referenceType.setProcessed(true);
                        inputProcessorChain.getSecurityContext().setIsInSignedContent();

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

        inputProcessorChain.processEvent(xmlEvent);
    }

    @Override
    public void doFinal(InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        List<ReferenceType> references = signatureType.getSignedInfo().getReference();
        for (int i = 0; i < references.size(); i++) {
            ReferenceType referenceType = references.get(i);
            if (!referenceType.isProcessed()) {
                throw new XMLSecurityException("Some signature references where not processed... Probably security header ordering problem?");
            }
        }
        inputProcessorChain.doFinal();
    }

    class InternalSignatureReferenceVerifier extends AbstractInputProcessor {
        private ReferenceType referenceType;

        private List<Transformer> transformers = new ArrayList<Transformer>();
        private DigestOutputStream digestOutputStream;
        private OutputStream bufferedDigestOutputStream;
        //todo: startElement still needed?? Is elementCounter not enough? Test overall code
        private QName startElement;
        private int elementCounter = 0;

        public InternalSignatureReferenceVerifier(SecurityProperties securityProperties, ReferenceType referenceType, QName startElement) throws XMLSecurityException {
            super(securityProperties);
            this.getAfterProcessors().add(SignatureReferenceVerifyInputProcessor.class.getName());
            this.startElement = startElement;
            this.referenceType = referenceType;
            try {
                createMessageDigest();
                buildTransformerChain();
            } catch (Exception e) {
                throw new XMLSecurityException(e.getMessage(), e);
            }
        }

        private void createMessageDigest() throws NoSuchAlgorithmException, NoSuchProviderException {
            String digestAlgorithm = JCEAlgorithmMapper.translateURItoJCEID(referenceType.getDigestMethod().getAlgorithm());
            MessageDigest messageDigest = MessageDigest.getInstance(digestAlgorithm, "BC");
            this.digestOutputStream = new DigestOutputStream(messageDigest);
            this.bufferedDigestOutputStream = new BufferedOutputStream(this.digestOutputStream);
        }

        private void buildTransformerChain() {
            transformers.add(new Canonicalizer20010315ExclOmitCommentsTransformer(null));
        }

        @Override
        public void processSecurityHeaderEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
            inputProcessorChain.processSecurityHeaderEvent(xmlEvent);
        }

        @Override
        public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {

            for (int i = 0; i < transformers.size(); i++) {
                Transformer transformer = transformers.get(i);
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
                        throw new XMLSecurityException(e);
                    }

                    byte[] calculatedDigest = this.digestOutputStream.getDigestValue();
                    byte[] storedDigest = org.bouncycastle.util.encoders.Base64.decode(referenceType.getDigestValue());

                    if (logger.isDebugEnabled()) {
                        logger.debug("Calculated Digest: " + new String(org.bouncycastle.util.encoders.Base64.encode(calculatedDigest)));
                        logger.debug("Stored Digest: " + new String(org.bouncycastle.util.encoders.Base64.encode(storedDigest)));
                    }

                    if (!MessageDigest.isEqual(storedDigest, calculatedDigest)) {
                        throw new XMLSecurityException("Digest verification failed");
                    }
                    inputProcessorChain.removeProcessor(this);
                    inputProcessorChain.getSecurityContext().unsetIsInSignedContent();
                }
            }
            inputProcessorChain.processEvent(xmlEvent);
        }
    }
}
