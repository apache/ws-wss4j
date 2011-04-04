/*
 * Copyright 1996-2011 itServe AG. All rights reserved.
 *
 * This software is the proprietary information of itServe AG
 * Bern Switzerland. Use is subject to license terms.
 *
 */
package org.swssf.test;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.swssf.WSSec;
import org.swssf.ext.*;
import org.swssf.test.utils.CustomW3CDOMStreamReader;
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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Properties;

/**
 * @author $Author: $
 * @version $Revision: $ $Date: $
 */
public class UsernameTokenTest extends AbstractTestBase {

    @Test
    public void testDefaultConfigurationInbound() throws Exception {
        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.USERNAME_TOKEN;
            Properties properties = new Properties();
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsse_Password.getNamespaceURI(), Constants.TAG_wsse_Password.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(((Element)nodeList.item(0)).getAttribute(Constants.ATT_NULL_Type.getLocalPart()), Constants.UsernameTokenPasswordType.PASSWORD_DIGEST.getNamespace());
        }

        //done UsernameToken; now verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            //securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(new CustomW3CDOMStreamReader(securedDocument));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testWrongUsername() throws Exception {
        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.USERNAME_TOKEN;
            Properties properties = new Properties();
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }

        //done UsernameToken; now verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl("wrongUsername"));
            //securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(new CustomW3CDOMStreamReader(securedDocument));

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

    //todo wrongUserName is supplied and this test must fail.
    //Username can't be checked in swssf, it must be done via SecurityEvent
    @Test
    public void testInboundPW_TEXT() throws Exception {
        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.USERNAME_TOKEN;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.PASSWORD_TYPE, WSConstants.PW_TEXT);
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsse_Password.getNamespaceURI(), Constants.TAG_wsse_Password.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(((Element)nodeList.item(0)).getAttribute(Constants.ATT_NULL_Type.getLocalPart()), Constants.UsernameTokenPasswordType.PASSWORD_TEXT.getNamespace());
        }

        //done UsernameToken; now verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl("wrongUsername"));
            //securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(new CustomW3CDOMStreamReader(securedDocument));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }
    }

    //wss4j bug. PWNONE throws an NPE...
    /*@Test
    public void testInboundPWNONE() throws Exception {
        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.USERNAME_TOKEN;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.PASSWORD_TYPE, WSConstants.PW_NONE);
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }

        javax.xml.transform.Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(System.out));

        //done UsernameToken; now verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            //securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(new CustomW3CDOMStreamReader(securedDocument));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }
    }*/

    @Test
    public void testInboundUT_SIGN() throws Exception {
        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGN_WITH_UT_KEY;
            Properties properties = new Properties();
            securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_wsse_Password.getNamespaceURI(), Constants.TAG_wsse_Password.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(((Element)nodeList.item(0)).getAttribute(Constants.ATT_NULL_Type.getLocalPart()), Constants.UsernameTokenPasswordType.PASSWORD_DIGEST.getNamespace());
        }

        //done UsernameToken; now verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(new CustomW3CDOMStreamReader(securedDocument));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
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
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8");
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_Password.getNamespaceURI(), Constants.TAG_wsse_Password.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(((Element)nodeList.item(0)).getAttribute(Constants.ATT_NULL_Type.getLocalPart()), Constants.UsernameTokenPasswordType.PASSWORD_DIGEST.getNamespace());
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
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8");
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
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8");
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_Password.getNamespaceURI(), Constants.TAG_wsse_Password.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(((Element)nodeList.item(0)).getAttribute(Constants.ATT_NULL_Type.getLocalPart()), Constants.UsernameTokenPasswordType.PASSWORD_TEXT.getNamespace());
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
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8");
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
            Assert.assertEquals(((Element)nodeList.item(0)).getAttribute(Constants.ATT_NULL_Type.getLocalPart()), Constants.UsernameTokenPasswordType.PASSWORD_DIGEST.getNamespace());

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
        Document securedDocument;

        {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.USERNAMETOKEN};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setTokenUser("transmitter");
            securityProperties.setUsernameTokenPasswordType(Constants.UsernameTokenPasswordType.PASSWORD_NONE);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8");
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            securedDocument = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
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
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(new CustomW3CDOMStreamReader(securedDocument));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_UsernameToken.getNamespaceURI(), Constants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }
    }
}
