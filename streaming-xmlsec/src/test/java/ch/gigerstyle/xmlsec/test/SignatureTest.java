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
package ch.gigerstyle.xmlsec.test;

import ch.gigerstyle.xmlsec.XMLSec;
import ch.gigerstyle.xmlsec.ext.*;
import ch.gigerstyle.xmlsec.test.utils.CustomW3CDOMStreamReader;
import ch.gigerstyle.xmlsec.test.utils.StAX2DOM;
import ch.gigerstyle.xmlsec.test.utils.XmlReaderToWriter;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Properties;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SignatureTest extends AbstractTestBase {

    //todo C14N inclusive

    @Test
    public void testSignatureDefaultConfigurationOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundXMLSec xmlSecOut = XMLSec.getOutboundXMLSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = xmlSecOut.processOutMessage(baos);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Reference.getNamespaceURI(), Constants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_soap11_Body.getNamespaceURI(), Constants.TAG_soap11_Body.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(Constants.ATT_wsu_Id.getNamespaceURI(), Constants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.startsWith("id-"), "wsu:id Attribute doesn't start with id");
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSignatureDefaultConfigurationInbound() throws Exception {

        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.SIGNATURE;
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }

        //done signature; now test sig-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            InboundXMLSec xmlSec = XMLSec.getInboundXMLSec(securityProperties);
            XMLStreamReader xmlStreamReader = xmlSec.processInMessage(new CustomW3CDOMStreamReader(securedDocument));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testSignaturePartsOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.addSignaturePart(new SecurePart("complexType", "http://www.w3.org/1999/XMLSchema", "Element"));
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundXMLSec xmlSecOut = XMLSec.getOutboundXMLSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = xmlSecOut.processOutMessage(baos);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Reference.getNamespaceURI(), Constants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 25);

            nodeList = document.getElementsByTagNameNS("http://www.w3.org/1999/XMLSchema", "complexType");
            Assert.assertEquals(nodeList.getLength(), 26);
            for (int i = 0; i < nodeList.getLength(); i++) {
                String idAttrValue = ((Element) nodeList.item(i)).getAttributeNS(Constants.ATT_wsu_Id.getNamespaceURI(), Constants.ATT_wsu_Id.getLocalPart());
                if (i == 10) {
                    Assert.assertSame(idAttrValue, "");
                } else {
                    Assert.assertNotSame(idAttrValue, "");
                    Assert.assertTrue(idAttrValue.startsWith("id-"), "wsu:id Attribute doesn't start with id");
                }
            }
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSignaturePartsInbound() throws Exception {

        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://www.w3.org/1999/XMLSchema}complexType;");
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }

        //done signature; now test sig-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            InboundXMLSec xmlSec = XMLSec.getInboundXMLSec(securityProperties);
            XMLStreamReader xmlStreamReader = xmlSec.processInMessage(new CustomW3CDOMStreamReader(securedDocument));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testSignatureKeyIdentifierIssuerSerialOutbound() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setSignatureKeyIdentifierType(Constants.KeyIdentifierType.ISSUER_SERIAL);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundXMLSec xmlSecOut = XMLSec.getOutboundXMLSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = xmlSecOut.processOutMessage(baos);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature/dsig:KeyInfo/wsse:SecurityTokenReference/dsig:X509Data/dsig:X509IssuerSerial/dsig:X509SerialNumber");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Reference.getNamespaceURI(), Constants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_soap11_Body.getNamespaceURI(), Constants.TAG_soap11_Body.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(Constants.ATT_wsu_Id.getNamespaceURI(), Constants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.startsWith("id-"), "wsu:id Attribute doesn't start with id");
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSignatureKeyIdentifierIssuerSerialInbound() throws Exception {

        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SIG_KEY_ID, "IssuerSerial");
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature/dsig:KeyInfo/wsse:SecurityTokenReference/dsig:X509Data/dsig:X509IssuerSerial/dsig:X509SerialNumber");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);
        }

        //done signature; now test sig-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            InboundXMLSec xmlSec = XMLSec.getInboundXMLSec(securityProperties);
            XMLStreamReader xmlStreamReader = xmlSec.processInMessage(new CustomW3CDOMStreamReader(securedDocument));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testSignatureKeyIdentifierBinarySecurityTokenDirectReferenceOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setSignatureKeyIdentifierType(Constants.KeyIdentifierType.BST_DIRECT_REFERENCE);
            securityProperties.setCallbackHandler(new ch.gigerstyle.xmlsec.test.CallbackHandlerImpl());

            OutboundXMLSec xmlSecOut = XMLSec.getOutboundXMLSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = xmlSecOut.processOutMessage(baos);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/wsse:BinarySecurityToken");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Reference.getNamespaceURI(), Constants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_soap11_Body.getNamespaceURI(), Constants.TAG_soap11_Body.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(Constants.ATT_wsu_Id.getNamespaceURI(), Constants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.startsWith("id-"), "wsu:id Attribute doesn't start with id");
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSignatureKeyIdentifierBinarySecurityTokenDirectReferenceInbound() throws Exception {

        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/wsse:BinarySecurityToken");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);
        }

        //done signature; now test sig-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            InboundXMLSec xmlSec = XMLSec.getInboundXMLSec(securityProperties);
            XMLStreamReader xmlStreamReader = xmlSec.processInMessage(new CustomW3CDOMStreamReader(securedDocument));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testSignatureKeyIdentifierBinarySecurityTokenEmbedded() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setSignatureKeyIdentifierType(Constants.KeyIdentifierType.BST_EMBEDDED);
            securityProperties.setCallbackHandler(new ch.gigerstyle.xmlsec.test.CallbackHandlerImpl());

            OutboundXMLSec xmlSecOut = XMLSec.getOutboundXMLSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = xmlSecOut.processOutMessage(baos);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:Reference/wsse:BinarySecurityToken");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Reference.getNamespaceURI(), Constants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_soap11_Body.getNamespaceURI(), Constants.TAG_soap11_Body.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(Constants.ATT_wsu_Id.getNamespaceURI(), Constants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.startsWith("id-"), "wsu:id Attribute doesn't start with id");
        }

        //done signature; now test sig-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            InboundXMLSec xmlSec = XMLSec.getInboundXMLSec(securityProperties);
            XMLStreamReader xmlStreamReader = xmlSec.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testSignatureKeyIdentifierX509KeyOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setSignatureKeyIdentifierType(Constants.KeyIdentifierType.X509_KEY_IDENTIFIER);
            securityProperties.setCallbackHandler(new ch.gigerstyle.xmlsec.test.CallbackHandlerImpl());

            OutboundXMLSec xmlSecOut = XMLSec.getOutboundXMLSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = xmlSecOut.processOutMessage(baos);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Reference.getNamespaceURI(), Constants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_soap11_Body.getNamespaceURI(), Constants.TAG_soap11_Body.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(Constants.ATT_wsu_Id.getNamespaceURI(), Constants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.startsWith("id-"), "wsu:id Attribute doesn't start with id");
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSignatureKeyIdentifierX509KeyInbound() throws Exception {

        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SIG_KEY_ID, "X509KeyIdentifier");
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);
        }

        //done signature; now test sig-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            InboundXMLSec xmlSec = XMLSec.getInboundXMLSec(securityProperties);
            XMLStreamReader xmlStreamReader = xmlSec.processInMessage(new CustomW3CDOMStreamReader(securedDocument));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testSignatureKeyIdentifierSubjectKeyOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setSignatureKeyIdentifierType(Constants.KeyIdentifierType.SKI_KEY_IDENTIFIER);
            securityProperties.setCallbackHandler(new ch.gigerstyle.xmlsec.test.CallbackHandlerImpl());

            OutboundXMLSec xmlSecOut = XMLSec.getOutboundXMLSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = xmlSecOut.processOutMessage(baos);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Reference.getNamespaceURI(), Constants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_soap11_Body.getNamespaceURI(), Constants.TAG_soap11_Body.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(Constants.ATT_wsu_Id.getNamespaceURI(), Constants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.startsWith("id-"), "wsu:id Attribute doesn't start with id");
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSignatureKeyIdentifierSubjectKeyInbound() throws Exception {

        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SIG_KEY_ID, "SKIKeyIdentifier");
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);
        }

        //done signature; now test sig-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            InboundXMLSec xmlSec = XMLSec.getInboundXMLSec(securityProperties);
            XMLStreamReader xmlStreamReader = xmlSec.processInMessage(new CustomW3CDOMStreamReader(securedDocument));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testSignatureKeyIdentifierThumbprintOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setSignatureKeyIdentifierType(Constants.KeyIdentifierType.THUMBPRINT_IDENTIFIER);
            securityProperties.setCallbackHandler(new ch.gigerstyle.xmlsec.test.CallbackHandlerImpl());

            OutboundXMLSec xmlSecOut = XMLSec.getOutboundXMLSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = xmlSecOut.processOutMessage(baos);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Reference.getNamespaceURI(), Constants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_soap11_Body.getNamespaceURI(), Constants.TAG_soap11_Body.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(Constants.ATT_wsu_Id.getNamespaceURI(), Constants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.startsWith("id-"), "wsu:id Attribute doesn't start with id");
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSignatureKeyIdentifierThumbprintInbound() throws Exception {

        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SIG_KEY_ID, "Thumbprint");
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);
        }

        //done signature; now test sig-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "1234567890".toCharArray());
            InboundXMLSec xmlSec = XMLSec.getInboundXMLSec(securityProperties);
            XMLStreamReader xmlStreamReader = xmlSec.processInMessage(new CustomW3CDOMStreamReader(securedDocument));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }
    }
}
