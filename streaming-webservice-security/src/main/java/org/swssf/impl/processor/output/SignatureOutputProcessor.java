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
package org.swssf.impl.processor.output;

import org.apache.commons.codec.binary.Base64;
import org.swssf.config.JCEAlgorithmMapper;
import org.swssf.config.TransformerAlgorithmMapper;
import org.swssf.ext.*;
import org.swssf.impl.SignaturePartDef;
import org.swssf.impl.transformer.canonicalizer.Canonicalizer20010315Transformer;
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
import java.util.*;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class SignatureOutputProcessor extends AbstractOutputProcessor {

    private List<SecurePart> secureParts;
    private List<SignaturePartDef> signaturePartDefList = new LinkedList<SignaturePartDef>();

    private InternalSignatureOutputProcessor activeInternalSignatureOutputProcessor = null;

    public SignatureOutputProcessor(SecurityProperties securityProperties) throws WSSecurityException {
        super(securityProperties);
        secureParts = securityProperties.getSignatureSecureParts();
    }

    public List<SignaturePartDef> getSignaturePartDefList() {
        return signaturePartDefList;
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            //avoid double signature when child elements matches too
            if (activeInternalSignatureOutputProcessor == null) {
                Iterator<SecurePart> securePartIterator = secureParts.iterator();
                while (securePartIterator.hasNext()) {
                    SecurePart securePart = securePartIterator.next();
                    if (securePart.getId() == null) {
                        if (startElement.getName().getLocalPart().equals(securePart.getName())
                                && startElement.getName().getNamespaceURI().equals(securePart.getNamespace())) {

                            logger.debug("Matched securePart for signature");
                            InternalSignatureOutputProcessor internalSignatureOutputProcessor = null;
                            try {
                                SignaturePartDef signaturePartDef = new SignaturePartDef();
                                signaturePartDef.setSigRefId("id-" + UUID.randomUUID().toString());//"EncDataId-1612925417"

                                signaturePartDefList.add(signaturePartDef);

                                boolean found = false;
                                List<Attribute> attributeList = new ArrayList<Attribute>();
                                Iterator<Attribute> attributeIterator = startElement.getAttributes();
                                while (attributeIterator.hasNext()) {
                                    Attribute attribute = attributeIterator.next();
                                    if (attribute.getName().equals(Constants.ATT_wsu_Id)) {
                                        signaturePartDef.setSigRefId(attribute.getValue());
                                        found = true;
                                    }
                                }
                                if (!found) {
                                    attributeList.add(createAttribute(Constants.ATT_wsu_Id, signaturePartDef.getSigRefId()));
                                    xmlEvent = cloneStartElementEvent(xmlEvent, attributeList);
                                }

                                internalSignatureOutputProcessor = new InternalSignatureOutputProcessor(getSecurityProperties(), signaturePartDef, startElement.getName());

                            } catch (NoSuchAlgorithmException e) {
                                throw new WSSecurityException(
                                        WSSecurityException.UNSUPPORTED_ALGORITHM, "unsupportedKeyTransp",
                                        new Object[]{"No such algorithm: " + getSecurityProperties().getSignatureAlgorithm()}, e
                                );
                            } catch (NoSuchProviderException e) {
                                throw new WSSecurityException(WSSecurityException.FAILURE, "noSecProvider", e);
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
        private org.swssf.impl.util.DigestOutputStream digestOutputStream;
        private List<Transformer> transformers = new LinkedList<Transformer>();

        InternalSignatureOutputProcessor(SecurityProperties securityProperties, SignaturePartDef signaturePartDef, QName startElement) throws WSSecurityException, NoSuchProviderException, NoSuchAlgorithmException {
            super(securityProperties);
            this.getAfterProcessors().add(SignatureOutputProcessor.class.getName());
            this.getBeforeProcessors().add(SignatureEndingOutputProcessor.class.getName());
            this.getBeforeProcessors().add(InternalSignatureOutputProcessor.class.getName());
            this.signaturePartDef = signaturePartDef;
            this.startElement = startElement;

            AlgorithmType algorithmID = JCEAlgorithmMapper.getAlgorithmMapping(getSecurityProperties().getSignatureDigestAlgorithm());
            MessageDigest messageDigest = MessageDigest.getInstance(algorithmID.getJCEName(), algorithmID.getJCEProvider());
            this.digestOutputStream = new org.swssf.impl.util.DigestOutputStream(messageDigest);
            this.bufferedDigestOutputStream = new BufferedOutputStream(digestOutputStream);

            Class<Transformer> transformerClass = TransformerAlgorithmMapper.getTransformerClass(getSecurityProperties().getSignatureCanonicalizationAlgorithm());
            Transformer transformer = null;
            try {
                if (Canonicalizer20010315Transformer.class.isAssignableFrom(transformerClass)) {
                    Constructor<Transformer> constructor = transformerClass.getConstructor(String.class);
                    transformer = constructor.newInstance((String) null);
                } else {
                    transformer = transformerClass.newInstance();
                }
            } catch (NoSuchMethodException e) {
                throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE, null, e);
            } catch (InstantiationException e) {
                throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE, null, e);
            } catch (IllegalAccessException e) {
                throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE, null, e);
            } catch (InvocationTargetException e) {
                throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE, null, e);
            }

            transformers.add(transformer);
        }

        @Override
        public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {

            Iterator<Transformer> transformerIterator = transformers.iterator();
            while (transformerIterator.hasNext()) {
                Transformer transformer = transformerIterator.next();
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
                        throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE, null, e);
                    }
                    String calculatedDigest = new String(Base64.encodeBase64(this.digestOutputStream.getDigestValue()));
                    logger.debug("Calculated Digest: " + calculatedDigest);
                    signaturePartDef.setDigestValue(calculatedDigest);

                    outputProcessorChain.removeProcessor(this);
                    //from now on signature is possible again
                    activeInternalSignatureOutputProcessor = null;
                    //todo the NSStack should be corrected...
                    xmlEvent = createEndElement(startElement);
                }
            }
            outputProcessorChain.processEvent(xmlEvent);
        }
    }
}
