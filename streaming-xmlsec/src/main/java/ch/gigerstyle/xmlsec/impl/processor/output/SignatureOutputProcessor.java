package ch.gigerstyle.xmlsec.impl.processor.output;

import ch.gigerstyle.xmlsec.config.JCEAlgorithmMapper;
import ch.gigerstyle.xmlsec.ext.*;
import ch.gigerstyle.xmlsec.impl.SignaturePartDef;
import ch.gigerstyle.xmlsec.impl.XMLEventNSAllocator;
import ch.gigerstyle.xmlsec.impl.transformer.canonicalizer.Canonicalizer20010315ExclOmitCommentsTransformer;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.*;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

/**
 * User: giger
 * Date: Jun 10, 2010
 * Time: 7:32:56 PM
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
public class SignatureOutputProcessor extends AbstractOutputProcessor {

    private List<SecurePart> secureParts;
    private List<SignaturePartDef> signaturePartDefList = new ArrayList<SignaturePartDef>();

    private InternalSignatureOutputProcessor activeInternalSignatureOutputProcessor = null;

    public SignatureOutputProcessor(SecurityProperties securityProperties) throws XMLSecurityException {
        super(securityProperties);
        secureParts = securityProperties.getSignatureSecureParts();
    }

    public List<SignaturePartDef> getSignaturePartDefList() {
        return signaturePartDefList;
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            //avoid double signature when child elements matches too
            if (activeInternalSignatureOutputProcessor == null) {
                for (int i = 0; i < secureParts.size(); i++) {
                    SecurePart securePart = secureParts.get(i);
                    if (securePart.getId() == null) {
                        if (startElement.getName().getLocalPart().equals(securePart.getName())
                                && startElement.getName().getNamespaceURI().equals(securePart.getNamespace())) {

                            logger.debug("Matched securePart for signature");
                            InternalSignatureOutputProcessor internalSignatureOutputProcessor = null;
                            try {
                                SignaturePartDef signaturePartDef = new SignaturePartDef();
                                signaturePartDef.setModifier(SignaturePartDef.Modifier.valueOf(securePart.getModifier()));
                                signaturePartDef.setSigRefId("id-" + UUID.randomUUID().toString());//"EncDataId-1612925417"
                                //signaturePartDef.setKeyId("#" + symmetricKeyId);//#EncKeyId-1483925398
                                //signaturePartDef.setSymmetricKey(symmetricKey);
                                signaturePartDefList.add(signaturePartDef);
                                internalSignatureOutputProcessor = new InternalSignatureOutputProcessor(getSecurityProperties(), signaturePartDef, startElement.getName());

                                List<Namespace> namespaceList = new ArrayList<Namespace>();
                                Iterator<Namespace> namespaceIterator = startElement.getNamespaces();
                                while (namespaceIterator.hasNext()) {
                                    Namespace namespace = namespaceIterator.next();
                                    namespaceList.add(namespace);
                                }
                                namespaceList.add(securityContext.<XMLEventNSAllocator>get(Constants.XMLEVENT_NS_ALLOCATOR).createNamespace(Constants.ATT_wsu_Id.getPrefix(), Constants.ATT_wsu_Id.getNamespaceURI()));

                                List<Attribute> attributeList = new ArrayList<Attribute>();
                                Iterator<Attribute> attributeIterator = startElement.getAttributes();
                                while (attributeIterator.hasNext()) {
                                    Attribute attribute = attributeIterator.next();
                                    attributeList.add(attribute);
                                }
                                attributeList.add(securityContext.<XMLEventNSAllocator>get(Constants.XMLEVENT_NS_ALLOCATOR).createAttribute(Constants.ATT_wsu_Id, signaturePartDef.getSigRefId()));
                                //todo this event should probably be allocated directly and not with our allocator to hold the stack consistent
                                //or also generate the matching endElement...
                                xmlEvent = securityContext.<XMLEventNSAllocator>get(Constants.XMLEVENT_NS_ALLOCATOR).createStartElement(startElement.getName(), namespaceList, attributeList);

                            } catch (NoSuchAlgorithmException e) {
                                throw new XMLSecurityException(e.getMessage(), e);
                            } catch (NoSuchProviderException e) {
                                throw new XMLSecurityException(e.getMessage(), e);
                            }

                            activeInternalSignatureOutputProcessor = internalSignatureOutputProcessor;
                            outputProcessorChain.addProcessor(internalSignatureOutputProcessor);
                            break;
                        }
                    }
                }
            }
        }
        outputProcessorChain.processEvent(xmlEvent);
    }

    class InternalSignatureOutputProcessor extends AbstractOutputProcessor {

        private SignaturePartDef signaturePartDef;
        private QName startElement;
        private int elementCounter = 0;

        private OutputStream bufferedDigestOutputStream;
        private ch.gigerstyle.xmlsec.impl.util.DigestOutputStream digestOutputStream;
        private List<Transformer> transformers = new ArrayList<Transformer>();

        InternalSignatureOutputProcessor(SecurityProperties securityProperties, SignaturePartDef signaturePartDef, QName startElement) throws XMLSecurityException, NoSuchProviderException, NoSuchAlgorithmException {
            super(securityProperties);
            this.getAfterProcessors().add(SignatureOutputProcessor.class.getName());
            this.getBeforeProcessors().add(SignatureEndingOutputProcessor.class.getName());
            this.getBeforeProcessors().add(InternalSignatureOutputProcessor.class.getName());
            this.signaturePartDef = signaturePartDef;
            this.startElement = startElement;

            String algorithmID = JCEAlgorithmMapper.translateURItoJCEID(getSecurityProperties().getSignatureDigestAlgorithm());
            MessageDigest messageDigest = MessageDigest.getInstance(algorithmID, "BC");
            this.digestOutputStream = new ch.gigerstyle.xmlsec.impl.util.DigestOutputStream(messageDigest);
            this.bufferedDigestOutputStream = new BufferedOutputStream(digestOutputStream);

            transformers.add(new Canonicalizer20010315ExclOmitCommentsTransformer(null));
        }

        @Override
        public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {

            for (int i = 0; i < transformers.size(); i++) {
                Transformer transformer = transformers.get(i);
                transformer.transform(xmlEvent, this.bufferedDigestOutputStream);
            }

            if (xmlEvent.isStartElement()) {
                elementCounter++;
            } else if (xmlEvent.isEndElement()) {
                elementCounter--;

                EndElement endElement = xmlEvent.asEndElement();

                if (endElement.getName().equals(this.startElement) && elementCounter == 0) {
                    try {
                        bufferedDigestOutputStream.close();
                    } catch (IOException e) {
                        throw new XMLSecurityException(e);
                    }
                    String calculatedDigest = new String(org.bouncycastle.util.encoders.Base64.encode(this.digestOutputStream.getDigestValue()));
                    logger.debug("Calculated Digest: " + calculatedDigest);
                    signaturePartDef.setDigestValue(calculatedDigest);

                    outputProcessorChain.removeProcessor(this);
                    //from now on signature is possible again
                    activeInternalSignatureOutputProcessor = null;
                }
            }
            outputProcessorChain.processEvent(xmlEvent);
        }
    }
}
