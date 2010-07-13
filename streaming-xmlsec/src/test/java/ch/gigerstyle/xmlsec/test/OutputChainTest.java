package ch.gigerstyle.xmlsec.test;

import ch.gigerstyle.xmlsec.ext.Constants;
import ch.gigerstyle.xmlsec.ext.OutboundXMLSec;
import ch.gigerstyle.xmlsec.ext.SecurityProperties;
import ch.gigerstyle.xmlsec.XMLSec;
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
public class OutputChainTest extends AbstractTestBase {

    @Test
    public void testEncryptionAction() throws Exception {
        SecurityProperties securityProperties = new SecurityProperties();
        Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT};
        securityProperties.setOutAction(actions);
        securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
        securityProperties.setEncryptionUser("receiver");

        OutboundXMLSec xmlSec = XMLSec.getOutboundXMLSec(securityProperties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = xmlSec.processOutMessage(baos);
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml"));
        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
        NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
        Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

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

        nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
        Assert.assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(Constants.TAG_wsu_Timestamp.getNamespaceURI(), Constants.TAG_wsu_Timestamp.getLocalPart());
        Assert.assertEquals(nodeList.getLength(), 0);
    }

    @Test
    public void testSignatureAction() throws Exception {
        SecurityProperties securityProperties = new SecurityProperties();
        Constants.Action[] actions = new Constants.Action[]{Constants.Action.SIGNATURE};
        securityProperties.setOutAction(actions);
        securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
        securityProperties.setSignatureUser("receiver");
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());

        OutboundXMLSec xmlSec = XMLSec.getOutboundXMLSec(securityProperties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = xmlSec.processOutMessage(baos);
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml"));
        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
        NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
        Assert.assertEquals(nodeList.getLength(), 1);

        Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

        nodeList = document.getElementsByTagNameNS(Constants.TAG_soap11_Body.getNamespaceURI(), Constants.TAG_soap11_Body.getLocalPart());
        Assert.assertEquals(nodeList.getLength(), 1);

        Node attr = nodeList.item(0).getAttributes().getNamedItemNS(Constants.ATT_wsu_Id.getNamespaceURI(), Constants.ATT_wsu_Id.getLocalPart());
        Assert.assertNotNull(attr);

        nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
        Assert.assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(Constants.TAG_wsu_Timestamp.getNamespaceURI(), Constants.TAG_wsu_Timestamp.getLocalPart());
        Assert.assertEquals(nodeList.getLength(), 0);
    }

    @Test
    public void testTimeStampAction() throws Exception {
        SecurityProperties securityProperties = new SecurityProperties();
        Constants.Action[] actions = new Constants.Action[]{Constants.Action.TIMESTAMP};
        securityProperties.setOutAction(actions);

        OutboundXMLSec xmlSec = XMLSec.getOutboundXMLSec(securityProperties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = xmlSec.processOutMessage(baos);
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml"));
        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

        NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_wsu_Timestamp.getNamespaceURI(), Constants.TAG_wsu_Timestamp.getLocalPart());
        Assert.assertEquals(nodeList.getLength(), 1);

        Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

        nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
        Assert.assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
        Assert.assertEquals(nodeList.getLength(), 0);
    }
}