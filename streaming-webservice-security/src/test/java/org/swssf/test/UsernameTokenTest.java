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

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.swssf.WSSec;
import org.swssf.ext.*;
import org.swssf.securityEvent.SecurityEvent;
import org.swssf.securityEvent.SecurityEventListener;
import org.swssf.securityEvent.UsernameTokenSecurityEvent;
import org.swssf.test.utils.StAX2DOM;
import org.swssf.test.utils.XmlReaderToWriter;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Properties;

/**
 * @author $Author: $
 * @version $Revision: $ $Date: $
 */
public class UsernameTokenTest extends AbstractTestBase {

    @Test
    public void testDefaultConfigurationInbound() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.USERNAME_TOKEN;
            Properties properties = new Properties();
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsse_Password.getNamespaceURI(), Constants.TAG_wsse_Password.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(((Element) nodeList.item(0)).getAttribute(Constants.ATT_NULL_Type.getLocalPart()), Constants.UsernameTokenPasswordType.PASSWORD_DIGEST.getNamespace());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done UsernameToken; now verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            //securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testWrongUsername() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.USERNAME_TOKEN;
            Properties properties = new Properties();
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done UsernameToken; now verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl("wrongUsername"));
            //securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Expected XMLStreamException");
            } catch (XMLStreamException e) {
                Assert.assertNotNull(e.getCause());
                Assert.assertTrue(e.getCause() instanceof WSSecurityException);
                Assert.assertEquals(e.getCause().getMessage(), "The security token could not be authenticated or authorized");
            }
        }
    }

    //Username can't be checked in swssf, it must be done via SecurityEvent
    @Test
    public void testInboundPW_TEXT() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.USERNAME_TOKEN;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.PASSWORD_TYPE, WSConstants.PW_TEXT);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsse_Password.getNamespaceURI(), Constants.TAG_wsse_Password.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(((Element) nodeList.item(0)).getAttribute(Constants.ATT_NULL_Type.getLocalPart()), Constants.UsernameTokenPasswordType.PASSWORD_TEXT.getNamespace());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done UsernameToken; now verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl("username"));
            //securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            SecurityEventListener securityEventListener = new SecurityEventListener() {
                public void registerSecurityEvent(SecurityEvent securityEvent) throws WSSecurityException {
                    if (securityEvent instanceof UsernameTokenSecurityEvent) {
                        UsernameTokenSecurityEvent usernameTokenSecurityEvent = (UsernameTokenSecurityEvent) securityEvent;
                        if (!"username".equals(usernameTokenSecurityEvent.getUsername())) {
                            throw new WSSecurityException("Wrong username");
                        }
                    }
                }
            };

            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), new ArrayList<SecurityEvent>(), securityEventListener);

            try {
                Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Expected XMLStreamException");
            } catch (XMLStreamException e) {
                Assert.assertEquals(e.getMessage(), "org.swssf.ext.WSSecurityException: Wrong username");
            }
        }
    }

    //wss4j bug. PWNONE throws an NPE...
    /*@Test
    public void testInboundPWNONE() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.USERNAME_TOKEN;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.PASSWORD_TYPE, WSConstants.PW_NONE);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done UsernameToken; now verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            //securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }
    }
    */

    @Test
    public void testInboundUT_SIGN() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGN_WITH_UT_KEY;
            Properties properties = new Properties();
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done UsernameToken; now verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testReusedNonce() throws Exception {
        String req = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                "<env:Envelope xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "    <env:Header>" +
                "       <wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" env:mustUnderstand=\"1\">" +
                "           <wsse:UsernameToken wsu:Id=\"UsernameToken-1\">" +
                "               <wsse:Username>transmitter</wsse:Username>" +
                "               <wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">HJuU+E+LKyZyC7k1BX7GF7kyACY=</wsse:Password>" +
                "               <wsse:Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">Ex2YESUvsa1qne1m6TM8XA==</wsse:Nonce>" +
                "               <wsu:Created>2011-05-21T17:14:42.545Z</wsu:Created>" +
                "           </wsse:UsernameToken>" +
                "       </wsse:Security>\n" +
                "    </env:Header>\n" +
                "    <env:Body>\n" +
                "    </env:Body>\n" +
                "</env:Envelope>";

        SecurityProperties securityProperties = new SecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
        XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(req.getBytes())));
        StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

        try {
            xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(req.getBytes())));
            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Assert.assertEquals(e.getMessage(), "org.swssf.ext.WSSecurityException: The security token could not be authenticated or authorized");
        }
    }

    @Test
    public void testDefaultConfigurationOutbound() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.USERNAMETOKEN};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setTokenUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_Password.getNamespaceURI(), Constants.TAG_wsse_Password.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(((Element) nodeList.item(0)).getAttribute(Constants.ATT_NULL_Type.getLocalPart()), Constants.UsernameTokenPasswordType.PASSWORD_DIGEST.getNamespace());
        }

        //done UsernameToken; now verification:
        {
            String action = WSHandlerConstants.USERNAME_TOKEN;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testOutboundPW_NONE() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.USERNAMETOKEN};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setTokenUser("transmitter");
            securityProperties.setUsernameTokenPasswordType(Constants.UsernameTokenPasswordType.PASSWORD_NONE);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_Password.getNamespaceURI(), Constants.TAG_wsse_Password.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }

        //done UsernameToken; now verification:
        {
            String action = WSHandlerConstants.USERNAME_TOKEN;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testOutboundPW_TEXT() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.USERNAMETOKEN};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setTokenUser("transmitter");
            securityProperties.setUsernameTokenPasswordType(Constants.UsernameTokenPasswordType.PASSWORD_TEXT);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_Password.getNamespaceURI(), Constants.TAG_wsse_Password.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(((Element) nodeList.item(0)).getAttribute(Constants.ATT_NULL_Type.getLocalPart()), Constants.UsernameTokenPasswordType.PASSWORD_TEXT.getNamespace());
        }

        //done UsernameToken; now verification:
        {
            String action = WSHandlerConstants.USERNAME_TOKEN;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testOutboundSign() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.USERNAMETOKEN_SIGN};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setTokenUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_Password.getNamespaceURI(), Constants.TAG_wsse_Password.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(((Element) nodeList.item(0)).getAttribute(Constants.ATT_NULL_Type.getLocalPart()), Constants.UsernameTokenPasswordType.PASSWORD_DIGEST.getNamespace());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Reference.getNamespaceURI(), Constants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(Constants.NS_SOAP11, Constants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(Constants.ATT_wsu_Id.getNamespaceURI(), Constants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.startsWith("id-"), "wsu:id Attribute doesn't start with id");
        }

        //done UsernameToken; now verification:
        {
            String action = WSHandlerConstants.SIGN_WITH_UT_KEY + " " + WSHandlerConstants.USERNAME_TOKEN;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testInboundOutboundPW_NONE() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.USERNAMETOKEN};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setTokenUser("transmitter");
            securityProperties.setUsernameTokenPasswordType(Constants.UsernameTokenPasswordType.PASSWORD_NONE);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document securedDocument = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsse_Password.getNamespaceURI(), Constants.TAG_wsse_Password.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }

        //done UsernameToken; now verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }
    }
}
