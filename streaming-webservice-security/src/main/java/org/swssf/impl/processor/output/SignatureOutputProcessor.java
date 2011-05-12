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
import org.swssf.ext.*;
import org.swssf.impl.SignaturePartDef;
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
                SecurePart securePart = securePartMatches(startElement, outputProcessorChain);
                if (securePart != null) {

                    logger.debug("Matched securePart for signature");
                    InternalSignatureOutputProcessor internalSignatureOutputProcessor = null;
                    try {
                        SignaturePartDef signaturePartDef = new SignaturePartDef();
                        if (securePart.getIdToSign() == null) {
                            signaturePartDef.setSigRefId("id-" + UUID.randomUUID().toString());
                            signaturePartDef.setC14nAlgo(getSecurityProperties().getSignatureCanonicalizationAlgorithm());

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
                        } else {
                            if (Constants.SOAPMESSAGE_NS10_STRTransform.equals(securePart.getName())) {
                                signaturePartDef.setSigRefId(securePart.getIdToReference());
                                signaturePartDef.setTransformAlgo(Constants.SOAPMESSAGE_NS10_STRTransform);
                                signaturePartDef.setC14nAlgo(Constants.NS_C14N_EXCL);
                            } else {
                                signaturePartDef.setSigRefId(securePart.getIdToSign());
                                signaturePartDef.setC14nAlgo(getSecurityProperties().getSignatureCanonicalizationAlgorithm());
                            }
                        }

                        signaturePartDefList.add(signaturePartDef);
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
                }
            }
        }
        outputProcessorChain.processEvent(xmlEvent);
    }

    private SecurePart securePartMatches(StartElement startElement, OutputProcessorChain outputProcessorChain) {
        SecurePart securePart = securePartMatches(startElement, this.secureParts);
        if (securePart != null) {
            return securePart;
        }
        List<SecurePart> secureParts = outputProcessorChain.getSecurityContext().<SecurePart>getAsList(SecurePart.class);
        if (secureParts == null) {
            return null;
        }
        return securePartMatches(startElement, secureParts);
    }

    private SecurePart securePartMatches(StartElement startElement, List<SecurePart> secureParts) {
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
                        if ((attributeName.equals(Constants.ATT_wsu_Id)
                                || attributeName.equals(Constants.ATT_NULL_Id)
                                || attributeName.equals(Constants.ATT_NULL_ID)
                                || attributeName.equals(Constants.ATT_NULL_AssertionID))
                                && attribute.getValue().equals(securePart.getIdToSign())) {
                            return securePart;
                        }
                    }
                }
            }
        }
        return null;
    }

    class InternalSignatureOutputProcessor extends AbstractOutputProcessor {

        private SignaturePartDef signaturePartDef;
        private QName startElement;
        private int elementCounter = 0;

        private OutputStream bufferedDigestOutputStream;
        private org.swssf.impl.util.DigestOutputStream digestOutputStream;
        private Transformer transformer;

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

            try {
                if (signaturePartDef.getTransformAlgo() != null) {
                    Transformer transformer = Utils.getTransformer("#default", this.bufferedDigestOutputStream, signaturePartDef.getC14nAlgo());
                    this.transformer = Utils.getTransformer(transformer, null, signaturePartDef.getTransformAlgo());
                } else {
                    transformer = Utils.getTransformer((String) null, this.bufferedDigestOutputStream, signaturePartDef.getC14nAlgo());
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
        }

        @Override
        public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {

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
                        throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE, null, e);
                    }
                    String calculatedDigest = new String(Base64.encodeBase64(this.digestOutputStream.getDigestValue()));
                    logger.debug("Calculated Digest: " + calculatedDigest);
                    signaturePartDef.setDigestValue(calculatedDigest);

                    outputProcessorChain.removeProcessor(this);
                    //from now on signature is possible again
                    activeInternalSignatureOutputProcessor = null;
                    xmlEvent = createEndElement(startElement);
                }
            }
            outputProcessorChain.processEvent(xmlEvent);
        }
    }
}
