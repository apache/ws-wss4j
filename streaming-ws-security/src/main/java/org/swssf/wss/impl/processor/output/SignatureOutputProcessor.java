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
package org.swssf.wss.impl.processor.output;

import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSecurityException;
import org.swssf.xmlsec.ext.OutputProcessorChain;
import org.swssf.xmlsec.ext.SecurePart;
import org.swssf.xmlsec.ext.XMLSecurityException;
import org.swssf.xmlsec.impl.SignaturePartDef;
import org.swssf.xmlsec.impl.processor.output.AbstractSignatureOutputProcessor;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SignatureOutputProcessor extends AbstractSignatureOutputProcessor {

    public SignatureOutputProcessor() throws XMLSecurityException {
        super();
    }

    @Override
    public void init(OutputProcessorChain outputProcessorChain) throws XMLSecurityException {
        super.init(outputProcessorChain);
        SignatureEndingOutputProcessor signatureEndingOutputProcessor = new SignatureEndingOutputProcessor(this);
        signatureEndingOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
        signatureEndingOutputProcessor.setAction(getAction());
        signatureEndingOutputProcessor.init(outputProcessorChain);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            //avoid double signature when child elements matches too
            if (getActiveInternalSignatureOutputProcessor() == null) {
                SecurePart securePart = securePartMatches(startElement, outputProcessorChain, securityProperties.getSignatureSecureParts());
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
                            @SuppressWarnings("unchecked")
                            Iterator<Attribute> attributeIterator = startElement.getAttributes();
                            while (attributeIterator.hasNext()) {
                                Attribute attribute = attributeIterator.next();
                                if (attribute.getName().equals(WSSConstants.ATT_wsu_Id)) {
                                    signaturePartDef.setSigRefId(attribute.getValue());
                                    found = true;
                                }
                            }
                            if (!found) {
                                attributeList.add(createAttribute(WSSConstants.ATT_wsu_Id, signaturePartDef.getSigRefId()));
                                xmlEvent = cloneStartElementEvent(xmlEvent, attributeList);
                            }
                        } else {
                            if (WSSConstants.SOAPMESSAGE_NS10_STRTransform.equals(securePart.getName())) {
                                signaturePartDef.setSigRefId(securePart.getIdToReference());
                                signaturePartDef.setTransformAlgo(WSSConstants.SOAPMESSAGE_NS10_STRTransform);
                                signaturePartDef.setC14nAlgo(WSSConstants.NS_C14N_EXCL);
                            } else {
                                signaturePartDef.setSigRefId(securePart.getIdToSign());
                                signaturePartDef.setC14nAlgo(getSecurityProperties().getSignatureCanonicalizationAlgorithm());
                            }
                        }

                        getSignaturePartDefList().add(signaturePartDef);
                        internalSignatureOutputProcessor = new InternalSignatureOutputProcessor(signaturePartDef, startElement.getName());
                        internalSignatureOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
                        internalSignatureOutputProcessor.setAction(getAction());
                        internalSignatureOutputProcessor.getAfterProcessors().add(SignatureOutputProcessor.class.getName());
                        internalSignatureOutputProcessor.getBeforeProcessors().add(SignatureEndingOutputProcessor.class.getName());
                        internalSignatureOutputProcessor.init(outputProcessorChain);

                    } catch (NoSuchAlgorithmException e) {
                        throw new WSSecurityException(
                                WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, "unsupportedKeyTransp",
                                e, "No such algorithm: " + getSecurityProperties().getSignatureAlgorithm()
                        );
                    } catch (NoSuchProviderException e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noSecProvider", e);
                    }

                    setActiveInternalSignatureOutputProcessor(internalSignatureOutputProcessor);
                }
            }
        }
        outputProcessorChain.processEvent(xmlEvent);
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
                        if ((attributeName.equals(WSSConstants.ATT_wsu_Id)
                                || attributeName.equals(WSSConstants.ATT_NULL_Id)
                                || attributeName.equals(WSSConstants.ATT_NULL_ID)
                                || attributeName.equals(WSSConstants.ATT_NULL_AssertionID))
                                && attribute.getValue().equals(securePart.getIdToSign())) {
                            return securePart;
                        }
                    }
                }
            }
        }
        return null;
    }
}
