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


import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.wss4j.stax.WSSec;
import org.apache.wss4j.stax.ext.OutboundWSSec;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.test.utils.XmlReaderToWriter;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;

public class OutputChainTest extends AbstractTestBase {

    @Test
    public void testEncryptionAction() throws Exception {
        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
        securityProperties.setOutAction(actions);
        securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.setEncryptionUser("receiver");

        OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
        NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
        Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

        nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
        Assert.assertEquals(nodeList.getLength(), 1);

        Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), "Body");
        NodeList childNodes = nodeList.item(0).getParentNode().getChildNodes();
        for (int i = 0; i < childNodes.getLength(); i++) {
            Node child = childNodes.item(i);
            if (child.getNodeType() == Node.TEXT_NODE) {
                Assert.assertEquals(child.getTextContent().trim(), "");
            } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                Assert.assertEquals(child, nodeList.item(0));
            } else {
                Assert.fail("Unexpected Node encountered");
            }
        }

        nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
        Assert.assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_wsu_Timestamp.getNamespaceURI(), WSSConstants.TAG_wsu_Timestamp.getLocalPart());
        Assert.assertEquals(nodeList.getLength(), 0);
    }

    @Test
    public void testSignatureAction() throws Exception {
        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
        securityProperties.setOutAction(actions);
        securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.setSignatureUser("receiver");
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());

        OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
        NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
        Assert.assertEquals(nodeList.getLength(), 1);

        Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

        nodeList = document.getElementsByTagNameNS(WSSConstants.NS_SOAP11, WSSConstants.TAG_soap_Body_LocalName);
        Assert.assertEquals(nodeList.getLength(), 1);

        Node attr = nodeList.item(0).getAttributes().getNamedItemNS(WSSConstants.ATT_wsu_Id.getNamespaceURI(), WSSConstants.ATT_wsu_Id.getLocalPart());
        Assert.assertNotNull(attr);

        nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
        Assert.assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_wsu_Timestamp.getNamespaceURI(), WSSConstants.TAG_wsu_Timestamp.getLocalPart());
        Assert.assertEquals(nodeList.getLength(), 0);
    }

    @Test
    public void testTimeStampAction() throws Exception {
        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP};
        securityProperties.setOutAction(actions);

        OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

        NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_wsu_Timestamp.getNamespaceURI(), WSSConstants.TAG_wsu_Timestamp.getLocalPart());
        Assert.assertEquals(nodeList.getLength(), 1);

        Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

        nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
        Assert.assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
        Assert.assertEquals(nodeList.getLength(), 0);
    }
}