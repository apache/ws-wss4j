/*
 * Copyright 1996-2011 itServe AG. All rights reserved.
 *
 * This software is the proprietary information of itServe AG
 * Bern Switzerland. Use is subject to license terms.
 *
 */
package org.swssf.test;

import org.apache.ws.security.handler.WSHandlerConstants;
import org.swssf.WSSec;
import org.swssf.ext.*;
import org.swssf.securityEvent.SecurityEvent;
import org.swssf.securityEvent.SecurityEventListener;
import org.swssf.test.utils.CustomW3CDOMStreamReader;
import org.swssf.test.utils.StAX2DOM;
import org.swssf.test.utils.XmlReaderToWriter;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.rpc.handler.MessageContext;
import javax.xml.soap.SOAPConstants;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Vector;

/**
 * @author $Author: $
 * @version $Revision: $ $Date: $
 */
public class SignatureConfirmationTest extends AbstractTestBase {

    @Test
    public void testDefaultConfigurationInbound() throws Exception {

        Vector sigv;
        Document securedDocument;
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE;
            MessageContext messageContext = doOutboundSecurityWithWSS4J_1(sourceDocument, action, new Properties(), SOAPConstants.SOAP_1_1_PROTOCOL);
            sigv = (Vector)messageContext.getProperty(WSHandlerConstants.SEND_SIGV);
            securedDocument = (Document) messageContext.getProperty(WSHandlerConstants.SND_SECURITY);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }

        final List<SecurityEvent> securityEventList = new ArrayList<SecurityEvent>();
        //done signature; now test sig-verification:
        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            SecurityEventListener securityEventListener = new SecurityEventListener() {
                public void registerSecurityEvent(SecurityEvent securityEvent) throws WSSecurityException {
                    securityEventList.add(securityEvent);
                }
            };

            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(new CustomW3CDOMStreamReader(securedDocument), securityEventListener);

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }

        //so we have a request generated, now do the response:
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.SIGNATURE_CONFIRMATION};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", securityEventList);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Reference.getNamespaceURI(), Constants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse11_SignatureConfirmation.getNamespaceURI(), Constants.TAG_wsse11_SignatureConfirmation.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertNotSame(((Element) nodeList.item(0)).getAttribute(Constants.ATT_NULL_Value.getLocalPart()), "");
            Assert.assertNotNull(((Element)nodeList.item(0)).getAttribute(Constants.ATT_wsu_Id.getLocalPart()), "");
            Assert.assertTrue(((Element)nodeList.item(0)).getAttributeNS(Constants.ATT_wsu_Id.getNamespaceURI(), Constants.ATT_wsu_Id.getLocalPart()).startsWith("SigConf-"));

            nodeList = document.getElementsByTagNameNS(Constants.NS_SOAP11, Constants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(Constants.ATT_wsu_Id.getNamespaceURI(), Constants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.startsWith("id-"), "wsu:id Attribute doesn't start with id");
        }

        javax.xml.transform.Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.transform(new StreamSource(new ByteArrayInputStream(baos.toByteArray())), new StreamResult(System.out));

        //verify SigConf response:
        {
            String action = WSHandlerConstants.SIGNATURE;
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, SOAPConstants.SOAP_1_1_PROTOCOL, sigv);
        }
    }
}
