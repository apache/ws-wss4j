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
package org.apache.wss4j.stax.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.api.stax.ext.WSSConstants;
import org.apache.wss4j.api.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.setup.OutboundWSSec;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.wss4j.stax.test.utils.XmlReaderToWriter;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * A test for 2x Signatures + 2x Encryption. This is not supported for now, but these tests are mainly to
 * demonstrate an issue with WSS4J/Santuario hanging on the outbound side in certain scenarios.
 */
public class MultipleActionTest extends AbstractTestBase {

    @Test
    @org.junit.jupiter.api.Disabled
    public void testTwoSignatureActions() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.SIGNATURE);
            securityProperties.setActions(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Reference.getNamespaceURI(), WSSConstants.TAG_dsig_Reference.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.NS_SOAP11, WSSConstants.TAG_SOAP_BODY_LN);
            assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(WSSConstants.ATT_WSU_ID.getNamespaceURI(), WSSConstants.ATT_WSU_ID.getLocalPart());
            assertNotNull(idAttrValue);
            assertTrue(idAttrValue.length() > 0);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_c14nExcl_InclusiveNamespaces.getNamespaceURI(), WSSConstants.TAG_c14nExcl_InclusiveNamespaces.getLocalPart());
            assertEquals(nodeList.getLength(), 2);
            assertEquals(((Element) nodeList.item(0)).getAttributeNS(null, WSSConstants.ATT_NULL_PrefixList.getLocalPart()), "env");
            assertEquals(((Element) nodeList.item(1)).getAttributeNS(null, WSSConstants.ATT_NULL_PrefixList.getLocalPart()), "");
        }
    }

    @Test
    @org.junit.jupiter.api.Disabled
    public void testTwoEncryptionActions() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION);
            actions.add(WSSConstants.ENCRYPTION);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();
        }
    }

    @Test
    public void testDuplicateActions() throws Exception {
        WSSSecurityProperties properties = new WSSSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        properties.setSignatureUser("transmitter");
        properties.setCallbackHandler(new CallbackHandlerImpl());
        properties.setActions(actions);

        // Should work
        WSSec.getOutboundWSSec(properties);

        // Should throw an error on a duplicate Action
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        try {
            WSSec.getOutboundWSSec(properties);
            fail();
        } catch (WSSecurityException ex) {
            assertTrue(ex.getMessage().contains("Duplicate Actions are not allowed"));
        }
    }
}