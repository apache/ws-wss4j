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

import java.util.ArrayList;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;

import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.ext.WSSUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.AbstractOutputProcessor;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecNamespace;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

public class CustomTokenOutputProcessor extends AbstractOutputProcessor {

    public CustomTokenOutputProcessor() throws XMLSecurityException {
        super();
        addBeforeProcessor(WSSSignatureOutputProcessor.class.getName());
        addBeforeProcessor(EncryptedKeyOutputProcessor.class.getName());
    }
    
    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        try {
            String tokenId = outputProcessorChain.getSecurityContext().get(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_CUSTOM_TOKEN);
            if (tokenId == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
            }
                
            WSPasswordCallback wsPasswordCallback = new WSPasswordCallback(tokenId, WSPasswordCallback.CUSTOM_TOKEN);
            WSSUtils.doPasswordCallback(
                    ((WSSSecurityProperties) getSecurityProperties()).getCallbackHandler(),
                    wsPasswordCallback);
            Element customToken = wsPasswordCallback.getCustomToken();
            if (customToken == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
            }
            
            FinalUnknownTokenOutputProcessor outputProcessor = 
                new FinalUnknownTokenOutputProcessor(customToken);
            outputProcessor.setXMLSecurityProperties(getSecurityProperties());
            outputProcessor.setAction(getAction());
            outputProcessor.addBeforeProcessor(WSSSignatureOutputProcessor.class.getName());
            outputProcessor.addBeforeProcessor(EncryptedKeyOutputProcessor.class.getName());
            outputProcessor.init(outputProcessorChain);
        } finally {
            outputProcessorChain.removeProcessor(this);
        }
        outputProcessorChain.processEvent(xmlSecEvent);
    }
    
    class FinalUnknownTokenOutputProcessor extends AbstractOutputProcessor {

        private final Element token;

        FinalUnknownTokenOutputProcessor(Element token) throws XMLSecurityException {
            super();
            this.addAfterProcessor(CustomTokenOutputProcessor.class.getName());
            this.token = token;
        }
        
        @Override
        public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain)
            throws XMLStreamException, XMLSecurityException {
    
            outputProcessorChain.processEvent(xmlSecEvent);
    
            if (WSSUtils.isSecurityHeaderElement(xmlSecEvent, ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
                
                final QName headerElementName = new QName(token.getNamespaceURI(), token.getLocalName());
                WSSUtils.updateSecurityHeaderOrder(outputProcessorChain, headerElementName, getAction(), false);
    
                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
    
                outputToken(token, subOutputProcessorChain);
    
                outputProcessorChain.removeProcessor(this);
            }
        }
        
        private void outputToken(Element element, OutputProcessorChain outputProcessorChain)
                throws XMLStreamException, XMLSecurityException {

            NamedNodeMap namedNodeMap = element.getAttributes();
            List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(namedNodeMap.getLength());
            List<XMLSecNamespace> namespaces = new ArrayList<XMLSecNamespace>(namedNodeMap.getLength());
            for (int i = 0; i < namedNodeMap.getLength(); i++) {
                Attr attribute = (Attr) namedNodeMap.item(i);
                if (attribute.getPrefix() == null) {
                    attributes.add(
                            createAttribute(
                                    new QName(attribute.getNamespaceURI(), attribute.getLocalName()), attribute.getValue()));
                } else if ("xmlns".equals(attribute.getPrefix()) || "xmlns".equals(attribute.getLocalName())) {
                    namespaces.add(createNamespace(attribute.getLocalName(), attribute.getValue()));
                } else {
                    attributes.add(
                            createAttribute(
                                    new QName(attribute.getNamespaceURI(), attribute.getLocalName(), attribute.getPrefix()),
                                    attribute.getValue()));
                }
            }

            QName elementName = new QName(element.getNamespaceURI(), element.getLocalName(), element.getPrefix());
            createStartElementAndOutputAsEvent(outputProcessorChain, elementName, namespaces, attributes);
            NodeList childNodes = element.getChildNodes();
            for (int i = 0; i < childNodes.getLength(); i++) {
                Node childNode = childNodes.item(i);
                switch (childNode.getNodeType()) {
                    case Node.ELEMENT_NODE:
                        outputToken((Element) childNode, outputProcessorChain);
                        break;
                    case Node.TEXT_NODE:
                        createCharactersAndOutputAsEvent(outputProcessorChain, ((Text) childNode).getData());
                        break;
                }
            }
            createEndElementAndOutputAsEvent(outputProcessorChain, elementName);
        }
    }
}
