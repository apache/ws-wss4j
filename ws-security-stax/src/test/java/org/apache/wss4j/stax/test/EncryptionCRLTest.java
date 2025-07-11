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
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.api.stax.ext.WSSConstants;
import org.apache.wss4j.api.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.api.stax.securityToken.WSSecurityTokenConstants;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * This is a test for Certificate Revocation List checking before encryption.
 *
 * This test reuses the revoked certificate from SignatureCRLTest
 */
public class EncryptionCRLTest extends AbstractTestBase {

    @Test
    public void testEncryptionWithOutRevocationCheck() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("keys/wss40rev.jks"), "security".toCharArray());
            securityProperties.setEncryptionUser("wss40rev");
            securityProperties.setEncryptionKeyIdentifier(WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            xPathExpression = getXPath("/soap:Envelope/soap:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#aes256-cbc']");
            node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            assertNotNull(node);

            assertEquals(node.getParentNode().getParentNode().getLocalName(), "Body");
            NodeList childNodes = node.getParentNode().getParentNode().getChildNodes();
            for (int i = 0; i < childNodes.getLength(); i++) {
                Node child = childNodes.item(i);
                if (child.getNodeType() == Node.TEXT_NODE) {
                    assertEquals(child.getTextContent().trim(), "");
                } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                    assertEquals(child, nodeList.item(0));
                } else {
                    fail("Unexpected Node encountered");
                }
            }
        }
    }

    /**
     * TODO Re-enable once CRL issue fixed
     */
    @Test
    @org.junit.jupiter.api.Disabled
    public void testEncryptionWithRevocationCheck() throws Exception {
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION);
            securityProperties.setEnableRevocation(true);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("keys/wss40rev.jks"), "security".toCharArray());
            securityProperties.setEncryptionUser("wss40rev");
            securityProperties.setEncryptionKeyIdentifier(WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
            securityProperties.loadCRLCertStore(this.getClass().getClassLoader().getResource("wss40CACRL.pem"));

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            try {
                doOutboundSecurity(securityProperties, sourceDocument);
                fail("Expected failure on a revocation check");
            } catch (Exception ex) {
                assertNotNull(ex.getCause());
                assertTrue(ex.getCause() instanceof WSSecurityException);
            }
        }
    }

}