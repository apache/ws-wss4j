package ch.gigerstyle.xmlsec.test;

import ch.gigerstyle.xmlsec.ext.Constants;
import ch.gigerstyle.xmlsec.ext.SecurePart;
import ch.gigerstyle.xmlsec.ext.SecurityProperties;
import ch.gigerstyle.xmlsec.test.utils.CustomW3CDOMStreamReader;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

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
 * User: giger
 * Date: Jun 16, 2010
 * Time: 7:00:44 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class EncDecryptionTest extends AbstractTestBase {

    @Test
    public void testEncDecryptionDefaultConfigurationOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setEncryptionUser("receiver");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
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

        Document securedDocument;

        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.ENCRYPT;
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-1_5']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);
        }
        //test streaming decryption
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, new CustomW3CDOMStreamReader(securedDocument));

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
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionPart(new SecurePart("complexType", "http://www.w3.org/1999/XMLSchema", "Content"));

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_DataReference.getNamespaceURI(), Constants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 25);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 25);

            for (int i = 0; i < nodeList.getLength(); i++) {
                Assert.assertEquals(((Element) nodeList.item(i).getParentNode()).getLocalName(), "complexType");
                Assert.assertEquals(((Element) nodeList.item(i).getParentNode()).getNamespaceURI(), "http://www.w3.org/1999/XMLSchema");
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

        Document securedDocument;

        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENCRYPTION_PARTS, "{Content}{http://www.w3.org/1999/XMLSchema}complexType;");
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }
        //test streaming decryption
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, new CustomW3CDOMStreamReader(securedDocument));

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
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionPart(new SecurePart("complexType", "http://www.w3.org/1999/XMLSchema", "Element"));

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");

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
    public void testEncDecryptionPartsElementInbound() throws Exception {

        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            //wss4j just encrypts the first found element and not all!
            properties.setProperty(WSHandlerConstants.ENCRYPTION_PARTS, "{Element}{http://www.w3.org/1999/XMLSchema}complexType;");
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }

        //done encryption; now test decryption:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setCallbackHandler(new ch.gigerstyle.xmlsec.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, new CustomW3CDOMStreamReader(securedDocument));

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
    public void testEncDecryptionUseThisCert() throws Exception {

        ByteArrayOutputStream baos;
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT};
            securityProperties.setOutAction(actions);

            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(this.getClass().getClassLoader().getResourceAsStream("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setEncryptionUseThisCertificate((X509Certificate) keyStore.getCertificate("receiver"));

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_DataReference.getNamespaceURI(), Constants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            Assert.assertEquals(((Element) nodeList.item(0).getParentNode()).getLocalName(), "Body");
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
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setCallbackHandler(new ch.gigerstyle.xmlsec.test.CallbackHandlerImpl());
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
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(Constants.KeyIdentifierType.ISSUER_SERIAL);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");

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

        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "IssuerSerial");
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/dsig:X509Data/dsig:X509IssuerSerial/dsig:X509SerialNumber");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);
        }

        //done encryption; now test decryption:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setCallbackHandler(new ch.gigerstyle.xmlsec.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, new CustomW3CDOMStreamReader(securedDocument));

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
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(Constants.KeyIdentifierType.BST_DIRECT_REFERENCE);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");

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

        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "DirectReference");
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/wsse:BinarySecurityToken");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);
        }

        //done encryption; now test decryption:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setCallbackHandler(new ch.gigerstyle.xmlsec.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, new CustomW3CDOMStreamReader(securedDocument));

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
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(Constants.KeyIdentifierType.BST_EMBEDDED);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");

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
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setCallbackHandler(new ch.gigerstyle.xmlsec.test.CallbackHandlerImpl());
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
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(Constants.KeyIdentifierType.X509_KEY_IDENTIFIER);
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");

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
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierX509KeyInbound() throws Exception {

        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "X509KeyIdentifier");
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);
        }

        //done encryption; now test decryption:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setCallbackHandler(new ch.gigerstyle.xmlsec.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, new CustomW3CDOMStreamReader(securedDocument));

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
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(Constants.KeyIdentifierType.SKI_KEY_IDENTIFIER);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");

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

        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "SKIKeyIdentifier");
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);
        }

        //done encryption; now test decryption:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setCallbackHandler(new ch.gigerstyle.xmlsec.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, new CustomW3CDOMStreamReader(securedDocument));

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
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(Constants.KeyIdentifierType.THUMBPRINT_IDENTIFIER);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");

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

        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "Thumbprint");
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);
        }

        //done encryption; now test decryption:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setCallbackHandler(new ch.gigerstyle.xmlsec.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, new CustomW3CDOMStreamReader(securedDocument));

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
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(Constants.KeyIdentifierType.ISSUER_SERIAL);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");

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
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setCallbackHandler(new ch.gigerstyle.xmlsec.test.CallbackHandlerImpl());
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
}
