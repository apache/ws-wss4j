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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSUtils;
import org.swssf.wss.ext.WSSecurityException;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSecurityException;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.SignaturePartDef;
import org.apache.xml.security.stax.impl.processor.output.AbstractSignatureOutputProcessor;
import org.apache.xml.security.stax.impl.util.IDGenerator;

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * @author $Author: coheigea $
 * @version $Revision: 1354898 $ $Date: 2012-06-28 11:19:02 +0100 (Thu, 28 Jun 2012) $
 */
public class WSSSignatureOutputProcessor extends AbstractSignatureOutputProcessor {

    private static final transient Log logger = LogFactory.getLog(WSSSignatureOutputProcessor.class);

    public WSSSignatureOutputProcessor() throws XMLSecurityException {
        super();
    }

    @Override
    public void init(OutputProcessorChain outputProcessorChain) throws XMLSecurityException {
        super.init(outputProcessorChain);
        WSSSignatureEndingOutputProcessor signatureEndingOutputProcessor = new WSSSignatureEndingOutputProcessor(this);
        signatureEndingOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
        signatureEndingOutputProcessor.setAction(getAction());
        signatureEndingOutputProcessor.init(outputProcessorChain);
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        if (xmlSecEvent.getEventType() == XMLStreamConstants.START_ELEMENT) {
            XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();

            //avoid double signature when child elements matches too
            if (getActiveInternalSignatureOutputProcessor() == null) {
                SecurePart securePart = securePartMatches(xmlSecStartElement, outputProcessorChain, WSSConstants.SIGNATURE_PARTS);
                if (securePart != null) {

                    logger.debug("Matched securePart for signature");
                    InternalSignatureOutputProcessor internalSignatureOutputProcessor;
                    try {
                        SignaturePartDef signaturePartDef = new SignaturePartDef();
                        if (securePart.getIdToSign() == null) {
                            signaturePartDef.setGenerateXPointer(securePart.isGenerateXPointer());
                            signaturePartDef.setSigRefId(IDGenerator.generateID(null));
                            signaturePartDef.setC14nAlgo(getSecurityProperties().getSignatureCanonicalizationAlgorithm());

                            Attribute attribute = xmlSecStartElement.getAttributeByName(WSSConstants.ATT_wsu_Id);
                            if (attribute != null) {
                                signaturePartDef.setSigRefId(attribute.getValue());
                            } else {
                                List<XMLSecAttribute> attributeList = new ArrayList<XMLSecAttribute>(1);
                                attributeList.add(createAttribute(WSSConstants.ATT_wsu_Id, signaturePartDef.getSigRefId()));
                                xmlSecEvent = addAttributes(xmlSecStartElement, attributeList);
                            }
                        } else {
                            if (WSSConstants.SOAPMESSAGE_NS10_STRTransform.equals(securePart.getName().getLocalPart())) {
                                signaturePartDef.setSigRefId(securePart.getIdToReference());
                                signaturePartDef.setTransformAlgo(WSSConstants.SOAPMESSAGE_NS10_STRTransform);
                                signaturePartDef.setC14nAlgo(WSSConstants.NS_C14N_EXCL);
                            } else {
                                signaturePartDef.setSigRefId(securePart.getIdToSign());
                                signaturePartDef.setC14nAlgo(getSecurityProperties().getSignatureCanonicalizationAlgorithm());
                            }
                        }

                        getSignaturePartDefList().add(signaturePartDef);
                        internalSignatureOutputProcessor = new InternalSignatureOutputProcessor(signaturePartDef, xmlSecStartElement.getName());
                        internalSignatureOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
                        internalSignatureOutputProcessor.setAction(getAction());
                        internalSignatureOutputProcessor.addAfterProcessor(WSSSignatureOutputProcessor.class.getName());
                        internalSignatureOutputProcessor.addBeforeProcessor(WSSSignatureEndingOutputProcessor.class.getName());
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
                    //we can remove this processor when the whole body will be signed since there is
                    //nothing more which can be signed.
                    if (WSSConstants.TAG_soap_Body_LocalName.equals(xmlSecStartElement.getName().getLocalPart())
                            && WSSUtils.isInSOAPBody(xmlSecStartElement)) {
                        outputProcessorChain.removeProcessor(this);
                    }
                }
            }
        }
        outputProcessorChain.processEvent(xmlSecEvent);
    }

    protected SecurePart securePartMatches(XMLSecStartElement xmlSecStartElement, Map<Object, SecurePart> secureParts) {
        SecurePart securePart = secureParts.get(xmlSecStartElement.getName());
        if (securePart == null) {
            if (xmlSecStartElement.getOnElementDeclaredAttributes().size() == 0) {
                return null;
            }
            Attribute attribute = xmlSecStartElement.getAttributeByName(WSSConstants.ATT_wsu_Id);
            if (attribute != null) {
                securePart = secureParts.get(attribute.getValue());
                if (securePart != null) {
                    return securePart;
                }
            }
            attribute = xmlSecStartElement.getAttributeByName(WSSConstants.ATT_NULL_Id);
            if (attribute != null) {
                securePart = secureParts.get(attribute.getValue());
                if (securePart != null) {
                    return securePart;
                }
            }
            attribute = xmlSecStartElement.getAttributeByName(WSSConstants.ATT_NULL_ID);
            if (attribute != null) {
                securePart = secureParts.get(attribute.getValue());
                if (securePart != null) {
                    return securePart;
                }
            }
            attribute = xmlSecStartElement.getAttributeByName(WSSConstants.ATT_NULL_AssertionID);
            if (attribute != null) {
                securePart = secureParts.get(attribute.getValue());
                if (securePart != null) {
                    return securePart;
                }
            }
        }
        return securePart;
    }
}
