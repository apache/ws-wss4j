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
package org.swssf.test;

import org.apache.ws.security.handler.WSHandlerConstants;
import org.swssf.ext.Constants;
import org.swssf.ext.SecurePart;
import org.swssf.ext.SecurityProperties;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.soap.SOAPConstants;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Properties;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class EncDecryptionTest extends AbstractTestBase {

    @Test
    public void testEncDecryptionDefaultConfigurationOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_DataReference.getNamespaceURI(), Constants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            xPathExpression = getXPath("/env:Envelope/env:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#aes256-cbc']");
            node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            Assert.assertEquals(node.getParentNode().getParentNode().getLocalName(), "Body");
            NodeList childNodes = node.getParentNode().getParentNode().getChildNodes();
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
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionDefaultConfigurationInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-1_5']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }
        //test streaming decryption
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionPartsContentOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionPart(new SecurePart("complexType", "http://www.w3.org/1999/XMLSchema", SecurePart.Modifier.Content));

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_DataReference.getNamespaceURI(), Constants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 25);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 25);

            for (int i = 0; i < nodeList.getLength(); i++) {
                Assert.assertEquals(nodeList.item(i).getParentNode().getLocalName(), "complexType");
                Assert.assertEquals(nodeList.item(i).getParentNode().getNamespaceURI(), "http://www.w3.org/1999/XMLSchema");
                NodeList childNodes = nodeList.item(i).getParentNode().getChildNodes();
                for (int j = 0; j < childNodes.getLength(); j++) {
                    Node child = childNodes.item(j);
                    if (child.getNodeType() == Node.TEXT_NODE) {
                        Assert.assertEquals(child.getTextContent().trim(), "");
                    } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                        Assert.assertEquals(child, nodeList.item(i));
                    } else {
                        Assert.fail("Unexpected Node encountered");
                    }
                }
            }
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionPartsContentInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENCRYPTION_PARTS, "{Content}{http://www.w3.org/1999/XMLSchema}simpleType;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }
        //test streaming decryption
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionPartsElementOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionPart(new SecurePart("complexType", "http://www.w3.org/1999/XMLSchema", SecurePart.Modifier.Element));

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 25);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_DataReference.getNamespaceURI(), Constants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 25);

            nodeList = document.getElementsByTagNameNS("http://www.w3.org/1999/XMLSchema", "complexType");
            Assert.assertEquals(nodeList.getLength(), 0);
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionPartsHeaderOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionPart(new SecurePart("complexType", "http://www.w3.org/1999/XMLSchema", SecurePart.Modifier.Element));
            securityProperties.addEncryptionPart(new SecurePart("testEncryptedHeader", "http://www.example.com", SecurePart.Modifier.Element));

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-encryptedHeader.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 27);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_DataReference.getNamespaceURI(), Constants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 26);

            nodeList = document.getElementsByTagNameNS("http://www.w3.org/1999/XMLSchema", "complexType");
            Assert.assertEquals(nodeList.getLength(), 0);
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPT;
            Document doc = doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionPartsElementInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            //wss4j just encrypts the first found element and not all!
            properties.setProperty(WSHandlerConstants.ENCRYPTION_PARTS, "{Element}{http://www.w3.org/1999/XMLSchema}simpleType;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new org.swssf.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionPartsHeaderInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-encryptedHeader.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            //wss4j just encrypts the first found element and not all!
            properties.setProperty(WSHandlerConstants.ENCRYPTION_PARTS, "{Header}{http://www.example.com}testEncryptedHeader;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new org.swssf.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse11_EncryptedHeader.getNamespaceURI(), Constants.TAG_wsse11_EncryptedHeader.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
    }

    @Test
    public void testEncDecryptionUseThisCert() throws Exception {

        ByteArrayOutputStream baos;
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT};
            securityProperties.setOutAction(actions);

            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(this.getClass().getClassLoader().getResourceAsStream("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUseThisCertificate((X509Certificate) keyStore.getCertificate("receiver"));

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_DataReference.getNamespaceURI(), Constants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
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
        }

        //done encryption; now test decryption:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new org.swssf.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, new ByteArrayInputStream(baos.toByteArray()));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierIssuerSerialOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(Constants.KeyIdentifierType.ISSUER_SERIAL);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/dsig:X509Data/dsig:X509IssuerSerial/dsig:X509SerialNumber");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_DataReference.getNamespaceURI(), Constants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierIssuerSerialInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "IssuerSerial");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/dsig:X509Data/dsig:X509IssuerSerial/dsig:X509SerialNumber");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new org.swssf.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierBinarySecurityTokenDirectReferenceOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(Constants.KeyIdentifierType.BST_DIRECT_REFERENCE);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/wsse:BinarySecurityToken");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_DataReference.getNamespaceURI(), Constants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierBinarySecurityTokenDirectReferenceInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "DirectReference");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/wsse:BinarySecurityToken");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new org.swssf.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierBinarySecurityTokenDirectReferenceAtTheEndOfTheSecurityHeaderInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "DirectReference");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/wsse:BinarySecurityToken");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);
            Element parentElement = (Element) node.getParentNode();
            parentElement.removeChild(node);
            parentElement.appendChild(node);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new org.swssf.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierBinarySecurityTokenEmbedded() throws Exception {

        ByteArrayOutputStream baos;
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(Constants.KeyIdentifierType.BST_EMBEDDED);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:Reference/wsse:BinarySecurityToken");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_DataReference.getNamespaceURI(), Constants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }

        //done encryption; now test decryption:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new org.swssf.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, new ByteArrayInputStream(baos.toByteArray()));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierX509KeyOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(Constants.KeyIdentifierType.X509_KEY_IDENTIFIER);
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_DataReference.getNamespaceURI(), Constants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.IS_BSP_COMPLIANT, "false");
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, SOAPConstants.SOAP_1_1_PROTOCOL, properties, false);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierX509KeyInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "X509KeyIdentifier");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new org.swssf.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierSubjectKeyOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(Constants.KeyIdentifierType.SKI_KEY_IDENTIFIER);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_DataReference.getNamespaceURI(), Constants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierSubjectKeyInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "SKIKeyIdentifier");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new org.swssf.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierThumbprintOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(Constants.KeyIdentifierType.THUMBPRINT_IDENTIFIER);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_DataReference.getNamespaceURI(), Constants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierThumbprintInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "Thumbprint");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new org.swssf.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testDecryptionReferenceListOutsideEncryptedKey() throws Exception {

        ByteArrayOutputStream baos;
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(Constants.KeyIdentifierType.ISSUER_SERIAL);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/dsig:X509Data/dsig:X509IssuerSerial/dsig:X509SerialNumber");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_DataReference.getNamespaceURI(), Constants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            //move ReferenceList...
            TransformerFactory transFact = TransformerFactory.newInstance();
            Transformer trans = transFact.newTransformer(new StreamSource(this.getClass().getClassLoader().getResourceAsStream("xsl/testDecryptionReferenceListOutsideEncryptedKey.xsl")));
            baos.reset();
            trans.transform(new DOMSource(document), new StreamResult(baos));

        }

        //done encryption; now test decryption:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new org.swssf.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, new ByteArrayInputStream(baos.toByteArray()));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionSuperEncryptionInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

            securedDocument = doOutboundSecurityWithWSS4J(new ByteArrayInputStream(baos.toByteArray()), action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-1_5']");
            NodeList nodeList = (NodeList) xPathExpression.evaluate(securedDocument, XPathConstants.NODESET);
            Assert.assertEquals(nodeList.getLength(), 2);

            transformer = TRANSFORMER_FACTORY.newTransformer();
            baos.reset();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }
        //test streaming decryption
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }
}
