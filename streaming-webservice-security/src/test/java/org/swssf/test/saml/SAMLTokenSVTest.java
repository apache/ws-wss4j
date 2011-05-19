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
package org.swssf.test.saml;

import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.saml.ext.builder.SAML1Constants;
import org.apache.ws.security.saml.ext.builder.SAML2Constants;
import org.opensaml.common.SAMLVersion;
import org.swssf.WSSec;
import org.swssf.ext.*;
import org.swssf.securityEvent.SecurityEvent;
import org.swssf.test.AbstractTestBase;
import org.swssf.test.CallbackHandlerImpl;
import org.swssf.test.utils.StAX2DOM;
import org.swssf.test.utils.XmlReaderToWriter;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

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
public class SAMLTokenSVTest extends AbstractTestBase {

    @Test
    public void testSAML1AuthnAssertionOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.SAML_TOKEN_SIGNED};
            securityProperties.setOutAction(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            callbackHandler.setStatement(CallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML1Constants.CONF_SENDER_VOUCHES);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            securityProperties.setCallbackHandler(callbackHandler);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Reference.getNamespaceURI(), Constants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);

            nodeList = document.getElementsByTagNameNS(Constants.NS_SOAP11, Constants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(Constants.ATT_wsu_Id.getNamespaceURI(), Constants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.startsWith("id-"), "wsu:id Attribute doesn't start with id");
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSAML1AuthnAssertionInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
            callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML1Constants.CONF_SENDER_VOUCHES);
            callbackHandler.setIssuer("www.example.com");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SAML_PROP_FILE, "saml/saml-unsigned.properties");
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            properties.setProperty(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
    }

    @Test
    public void testSAML1AuthnAssertionSignedOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.SAML_TOKEN_SIGNED};
            securityProperties.setOutAction(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            callbackHandler.setStatement(CallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML1Constants.CONF_SENDER_VOUCHES);
            callbackHandler.setIssuer("www.example.com");
            securityProperties.setCallbackHandler(callbackHandler);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_saml_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.item(1).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Reference.getNamespaceURI(), Constants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 3);
            String referenceId = ((Element) nodeList.item(1)).getAttributeNode(Constants.ATT_NULL_URI.getLocalPart()).getValue();
            nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_SecurityTokenReference.getNamespaceURI(), Constants.TAG_wsse_SecurityTokenReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            String tokenId = ((Element) nodeList.item(0)).getAttributeNodeNS(Constants.ATT_wsu_Id.getNamespaceURI(), Constants.ATT_wsu_Id.getLocalPart()).getValue();
            Assert.assertEquals(tokenId, Utils.dropReferenceMarker(referenceId));

            nodeList = document.getElementsByTagNameNS(Constants.NS_SOAP11, Constants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(Constants.ATT_wsu_Id.getNamespaceURI(), Constants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.startsWith("id-"), "wsu:id Attribute doesn't start with id");
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.SAML_TOKEN_SIGNED;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSAML1AuthnAssertionSignedInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
            callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML1Constants.CONF_SENDER_VOUCHES);
            callbackHandler.setIssuer("www.example.com");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SAML_PROP_FILE, "saml/saml-signed.properties");
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            properties.setProperty(WSHandlerConstants.SIG_KEY_ID, "X509KeyIdentifier");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
        }
    }

    @Test
    public void testSAML1AttrAssertionOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.SAML_TOKEN_SIGNED};
            securityProperties.setOutAction(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            callbackHandler.setStatement(CallbackHandlerImpl.Statement.ATTR);
            callbackHandler.setConfirmationMethod(SAML1Constants.CONF_SENDER_VOUCHES);
            callbackHandler.setIssuer("www.example.com");
            securityProperties.setCallbackHandler(callbackHandler);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_saml_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.item(1).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Reference.getNamespaceURI(), Constants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 3);

            nodeList = document.getElementsByTagNameNS(Constants.NS_SOAP11, Constants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(Constants.ATT_wsu_Id.getNamespaceURI(), Constants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.startsWith("id-"), "wsu:id Attribute doesn't start with id");
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.SAML_TOKEN_SIGNED;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSAML1AttrAssertionInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
            callbackHandler.setStatement(SAML1CallbackHandler.Statement.ATTR);
            callbackHandler.setConfirmationMethod(SAML1Constants.CONF_SENDER_VOUCHES);
            callbackHandler.setIssuer("www.example.com");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SAML_PROP_FILE, "saml/saml-unsigned.properties");
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            properties.setProperty(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
    }

    @Test
    public void testSAML2AuthnAssertionOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.SAML_TOKEN_SIGNED};
            securityProperties.setOutAction(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            callbackHandler.setSamlVersion(SAMLVersion.VERSION_20);
            callbackHandler.setStatement(CallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML2Constants.CONF_SENDER_VOUCHES);
            callbackHandler.setIssuer("www.example.com");
            securityProperties.setCallbackHandler(callbackHandler);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_saml_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.item(1).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Reference.getNamespaceURI(), Constants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 3);

            nodeList = document.getElementsByTagNameNS(Constants.NS_SOAP11, Constants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(Constants.ATT_wsu_Id.getNamespaceURI(), Constants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.startsWith("id-"), "wsu:id Attribute doesn't start with id");
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.SAML_TOKEN_SIGNED;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSAML2AuthnAssertionInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML2Constants.CONF_SENDER_VOUCHES);
            callbackHandler.setIssuer("www.example.com");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SAML_PROP_FILE, "saml/saml-unsigned.properties");
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            properties.setProperty(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
    }

    @Test
    public void testSAML2AttrAssertionOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.SAML_TOKEN_SIGNED};
            securityProperties.setOutAction(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            callbackHandler.setSamlVersion(SAMLVersion.VERSION_20);
            callbackHandler.setStatement(CallbackHandlerImpl.Statement.ATTR);
            callbackHandler.setConfirmationMethod(SAML2Constants.CONF_SENDER_VOUCHES);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            securityProperties.setCallbackHandler(callbackHandler);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Reference.getNamespaceURI(), Constants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);

            nodeList = document.getElementsByTagNameNS(Constants.NS_SOAP11, Constants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(Constants.ATT_wsu_Id.getNamespaceURI(), Constants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.startsWith("id-"), "wsu:id Attribute doesn't start with id");
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSAML2AttrAssertionInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
            callbackHandler.setConfirmationMethod(SAML2Constants.CONF_SENDER_VOUCHES);
            callbackHandler.setIssuer("www.example.com");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SAML_PROP_FILE, "saml/saml-unsigned.properties");
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            properties.setProperty(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
    }
}
