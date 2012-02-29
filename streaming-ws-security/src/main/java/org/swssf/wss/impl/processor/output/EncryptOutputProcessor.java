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
import org.swssf.wss.ext.WSSDocumentContext;
import org.swssf.wss.ext.WSSSecurityProperties;
import org.swssf.xmlsec.ext.*;
import org.swssf.xmlsec.impl.EncryptionPartDef;
import org.swssf.xmlsec.impl.processor.output.AbstractEncryptOutputProcessor;

import javax.crypto.NoSuchPaddingException;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;

/**
 * Processor to encrypt XML structures
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class EncryptOutputProcessor extends AbstractEncryptOutputProcessor {

    public EncryptOutputProcessor(WSSSecurityProperties securityProperties, XMLSecurityConstants.Action action) throws XMLSecurityException {
        super(securityProperties, action);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            //avoid double encryption when child elements matches too
            if (getActiveInternalEncryptionOutputProcessor() == null) {
                SecurePart securePart = securePartMatches(startElement, outputProcessorChain, securityProperties.getEncryptionSecureParts());
                if (securePart != null) {
                    logger.debug("Matched securePart for encryption");
                    InternalEncryptionOutputProcessor internalEncryptionOutputProcessor = null;
                    try {
                        String tokenId = outputProcessorChain.getSecurityContext().get(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION);
                        SecurityTokenProvider securityTokenProvider = outputProcessorChain.getSecurityContext().getSecurityTokenProvider(tokenId);
                        EncryptionPartDef encryptionPartDef = new EncryptionPartDef();
                        encryptionPartDef.setModifier(securePart.getModifier());
                        encryptionPartDef.setEncRefId("ED-" + UUID.randomUUID().toString());
                        encryptionPartDef.setKeyId(securityTokenProvider.getId());
                        encryptionPartDef.setSymmetricKey(securityTokenProvider.getSecurityToken().getSecretKey(getSecurityProperties().getEncryptionSymAlgorithm(), null));
                        outputProcessorChain.getSecurityContext().putAsList(EncryptionPartDef.class, encryptionPartDef);
                        internalEncryptionOutputProcessor =
                                new InternalEncryptionOutputProcessor(
                                        ((WSSSecurityProperties) getSecurityProperties()),
                                        getAction(),
                                        encryptionPartDef,
                                        startElement,
                                        outputProcessorChain.getDocumentContext().getEncoding()
                                );
                    } catch (NoSuchAlgorithmException e) {
                        throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_ENCRYPTION, e);
                    } catch (NoSuchPaddingException e) {
                        throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_ENCRYPTION, e);
                    } catch (InvalidKeyException e) {
                        throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_ENCRYPTION, e);
                    } catch (IOException e) {
                        throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_ENCRYPTION, e);
                    }

                    setActiveInternalEncryptionOutputProcessor(internalEncryptionOutputProcessor);
                    outputProcessorChain.addProcessor(internalEncryptionOutputProcessor);
                }
            }
        }

        outputProcessorChain.processEvent(xmlEvent);
    }

    /**
     * Processor which handles the effective enryption of the data
     */
    class InternalEncryptionOutputProcessor extends AbstractInternalEncryptionOutputProcessor {

        private boolean doEncryptedHeader = false;

        InternalEncryptionOutputProcessor(WSSSecurityProperties securityProperties, XMLSecurityConstants.Action action, EncryptionPartDef encryptionPartDef,
                                          StartElement startElement, String encoding)
                throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, XMLStreamException {

            super(securityProperties, action, encryptionPartDef, startElement, encoding);
            this.getBeforeProcessors().add(org.swssf.wss.impl.processor.output.EncryptEndingOutputProcessor.class.getName());
            this.getBeforeProcessors().add(InternalEncryptionOutputProcessor.class.getName());
            this.getAfterProcessors().add(EncryptOutputProcessor.class.getName());
        }

        /**
         * Creates the Data structure around the cipher data
         */
        protected void processEventInternal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
            Map<QName, String> attributes = null;

            //WSS 1.1 EncryptedHeader Element:
            if (outputProcessorChain.getDocumentContext().getDocumentLevel() == 3
                    && ((WSSDocumentContext) outputProcessorChain.getDocumentContext()).isInSOAPHeader()) {
                doEncryptedHeader = true;

                attributes = new HashMap<QName, String>();

                @SuppressWarnings("unchecked")
                Iterator<Attribute> attributeIterator = getStartElement().getAttributes();
                while (attributeIterator.hasNext()) {
                    Attribute attribute = attributeIterator.next();
                    if (!attribute.isNamespace() &&
                            (WSSConstants.NS_SOAP11.equals(attribute.getName().getNamespaceURI()) ||
                                    WSSConstants.NS_SOAP12.equals(attribute.getName().getNamespaceURI()))) {
                        attributes.put(attribute.getName(), attribute.getValue());
                    }
                }
                createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse11_EncryptedHeader, attributes);
            }

            attributes = new HashMap<QName, String>();
            attributes.put(WSSConstants.ATT_NULL_Id, getEncryptionPartDef().getEncRefId());
            attributes.put(WSSConstants.ATT_NULL_Type, getEncryptionPartDef().getModifier().getModifier());
            createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_xenc_EncryptedData, attributes);

            attributes = new HashMap<QName, String>();
            attributes.put(WSSConstants.ATT_NULL_Algorithm, securityProperties.getEncryptionSymAlgorithm());
            createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_xenc_EncryptionMethod, attributes);

            createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_xenc_EncryptionMethod);
            createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig_KeyInfo, null);
            createKeyInfoStructure(outputProcessorChain);
            createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_dsig_KeyInfo);
            createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_xenc_CipherData, null);
            createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_xenc_CipherValue, null);

            /*
            <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Id="EncDataId-1612925417"
                Type="http://www.w3.org/2001/04/xmlenc#Content">
                <xenc:EncryptionMethod xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
                    Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc" />
                <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                    <wsse:SecurityTokenReference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                    <wsse:Reference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                        URI="#EncKeyId-1483925398" />
                    </wsse:SecurityTokenReference>
                </ds:KeyInfo>
                <xenc:CipherData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
                    <xenc:CipherValue xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
                    ...
                    </xenc:CipherValue>
                </xenc:CipherData>
            </xenc:EncryptedData>
             */
        }

        @Override
        protected void createKeyInfoStructure(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
            Map<QName, String> attributes;
            createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference, null);

            attributes = new HashMap<QName, String>();
            attributes.put(WSSConstants.ATT_NULL_URI, "#" + getEncryptionPartDef().getKeyId());
            createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_Reference, attributes);
            createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_Reference);
            createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference);
        }

        protected void doFinalInternal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {

            super.doFinalInternal(outputProcessorChain);

            if (doEncryptedHeader) {
                createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse11_EncryptedHeader);
            }
        }
    }
}
