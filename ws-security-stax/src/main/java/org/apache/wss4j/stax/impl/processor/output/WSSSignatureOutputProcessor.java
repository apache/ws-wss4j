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
package org.apache.wss4j.stax.impl.processor.output;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.impl.transformer.TransformIdentity;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSUtils;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.SignaturePartDef;
import org.apache.xml.security.stax.impl.processor.output.AbstractSignatureOutputProcessor;
import org.apache.xml.security.stax.impl.util.IDGenerator;

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.*;

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
                        signaturePartDef.setTransforms(securePart.getTransforms());
                        signaturePartDef.setExcludeVisibleC14Nprefixes(true);
                        String digestMethod = securePart.getDigestMethod();
                        if (digestMethod == null) {
                            digestMethod = getSecurityProperties().getSignatureDigestAlgorithm();
                        }
                        signaturePartDef.setDigestAlgo(digestMethod);

                        if (securePart.getIdToSign() == null) {
                            signaturePartDef.setGenerateXPointer(securePart.isGenerateXPointer());
                            signaturePartDef.setSigRefId(IDGenerator.generateID(null));

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
                                String[] transforms = new String[]{
                                        WSSConstants.SOAPMESSAGE_NS10_STRTransform,
                                        WSSConstants.NS_C14N_EXCL
                                };
                                signaturePartDef.setTransforms(transforms);
                            } else {
                                signaturePartDef.setSigRefId(securePart.getIdToSign());
                            }
                        }

                        getSignaturePartDefList().add(signaturePartDef);
                        internalSignatureOutputProcessor = new InternalWSSSignatureOutputProcessor(signaturePartDef, xmlSecStartElement);
                        internalSignatureOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
                        internalSignatureOutputProcessor.setAction(getAction());
                        internalSignatureOutputProcessor.addAfterProcessor(WSSSignatureOutputProcessor.class.getName());
                        internalSignatureOutputProcessor.addBeforeProcessor(WSSSignatureEndingOutputProcessor.class.getName());
                        internalSignatureOutputProcessor.init(outputProcessorChain);

                    } catch (NoSuchAlgorithmException e) {
                        throw new WSSecurityException(
                                WSSecurityException.ErrorCode.FAILED_SIGNATURE, "unsupportedKeyTransp",
                                e, "No such algorithm: " + getSecurityProperties().getSignatureAlgorithm()
                        );
                    } catch (NoSuchProviderException e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, "noSecProvider", e);
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

    @Override
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

    @Override
    protected Transformer buildTransformerChain(
            OutputStream outputStream, SignaturePartDef signaturePartDef, XMLSecStartElement xmlSecStartElement)
            throws XMLSecurityException {

        String[] transforms = signaturePartDef.getTransforms();

        if (transforms == null || transforms.length == 0) {
            Transformer transformer = new TransformIdentity();
            transformer.setOutputStream(outputStream);
            return transformer;
        }

        List<String> inclusiveNamespacePrefixes = null;

        Transformer parentTransformer = null;
        for (int i = transforms.length - 1; i >= 0; i--) {
            String transform = transforms[i];

            if (getSecurityProperties().isAddExcC14NInclusivePrefixes() &&
                    XMLSecurityConstants.NS_C14N_EXCL.equals(transform)) {

                Set<String> prefixSet = XMLSecurityUtils.getExcC14NInclusiveNamespacePrefixes(xmlSecStartElement, signaturePartDef.isExcludeVisibleC14Nprefixes());
                inclusiveNamespacePrefixes = new ArrayList<String>(prefixSet.size());

                StringBuilder prefixes = new StringBuilder();
                for (Iterator<String> iterator = prefixSet.iterator(); iterator.hasNext(); ) {
                    String prefix = iterator.next();
                    if (!inclusiveNamespacePrefixes.contains(prefix)) {
                        inclusiveNamespacePrefixes.add(prefix);
                    }
                    if (prefixes.length() != 0) {
                        prefixes.append(" ");
                    }
                    prefixes.append(prefix);
                }
                signaturePartDef.setInclusiveNamespacesPrefixes(prefixes.toString());
            }

            if (parentTransformer != null) {
                parentTransformer = XMLSecurityUtils.getTransformer(
                        parentTransformer, null, transform, XMLSecurityConstants.DIRECTION.OUT);
            } else {
                parentTransformer = XMLSecurityUtils.getTransformer(
                        inclusiveNamespacePrefixes, outputStream, transform, XMLSecurityConstants.DIRECTION.OUT);
            }
        }
        return parentTransformer;
    }

    class InternalWSSSignatureOutputProcessor extends InternalSignatureOutputProcessor {

        public InternalWSSSignatureOutputProcessor(SignaturePartDef signaturePartDef, XMLSecStartElement xmlSecStartElement) throws XMLSecurityException, NoSuchProviderException, NoSuchAlgorithmException {
            super(signaturePartDef, xmlSecStartElement);
            this.addBeforeProcessor(InternalWSSSignatureOutputProcessor.class.getName());
        }
    }
}
