package ch.gigerstyle.xmlsec.test;

import ch.gigerstyle.xmlsec.*;
import ch.gigerstyle.xmlsec.test.utils.StAX2DOM;
import ch.gigerstyle.xmlsec.test.utils.XmlReaderToWriter;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

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
public class EncDecryptionTests extends AbstractTestBase {

    @Test
    public void testEncDecryptionDefaultConfiguration() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setEncryptionUser("receiver");


            OutboundXMLSec xmlSecOut = XMLSec.getOutboundXMLSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = xmlSecOut.processOutMessage(baos);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xmlenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xmlenc_EncryptedKey.getLocalPart());
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
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundXMLSec xmlSec = XMLSec.getInboundXMLSec(securityProperties);
            XMLStreamReader xmlStreamReader = xmlSec.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xmlenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xmlenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
            /*
            DetailedDiff detailedDiff = new DetailedDiff(
                    new Diff(
                            new InputStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml")),
                            new InputStreamReader(new ByteArrayInputStream(baos.toByteArray()))));
            List allDifferences = detailedDiff.getAllDifferences();
            Assert.assertEquals(allDifferences.size(), 2, detailedDiff.toString());
            */
        }
    }

    @Test
    public void testEncDecryptionPartsContent() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionSecurePart(new SecurePart("complexType", "http://www.w3.org/1999/XMLSchema", "Content"));

            OutboundXMLSec xmlSecOut = XMLSec.getOutboundXMLSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = xmlSecOut.processOutMessage(baos);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xmlenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xmlenc_EncryptedKey.getLocalPart());
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
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundXMLSec xmlSec = XMLSec.getInboundXMLSec(securityProperties);
            XMLStreamReader xmlStreamReader = xmlSec.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xmlenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xmlenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionPartsElement() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionSecurePart(new SecurePart("complexType", "http://www.w3.org/1999/XMLSchema", "Element"));

            OutboundXMLSec xmlSecOut = XMLSec.getOutboundXMLSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = xmlSecOut.processOutMessage(baos);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xmlenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xmlenc_EncryptedKey.getLocalPart());
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
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundXMLSec xmlSec = XMLSec.getInboundXMLSec(securityProperties);
            XMLStreamReader xmlStreamReader = xmlSec.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xmlenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xmlenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionUseThisCert() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT};
            securityProperties.setOutAction(actions);

            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(this.getClass().getClassLoader().getResourceAsStream("receiver.jks"), "1234567890".toCharArray());
            securityProperties.setEncryptionUseThisCertificate((X509Certificate)keyStore.getCertificate("receiver"));

            OutboundXMLSec xmlSecOut = XMLSec.getOutboundXMLSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = xmlSecOut.processOutMessage(baos);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xmlenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xmlenc_EncryptedKey.getLocalPart());
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
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundXMLSec xmlSec = XMLSec.getInboundXMLSec(securityProperties);
            XMLStreamReader xmlStreamReader = xmlSec.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xmlenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xmlenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }
}
