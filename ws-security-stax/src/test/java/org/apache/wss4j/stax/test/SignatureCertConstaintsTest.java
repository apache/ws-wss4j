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
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Pattern;

import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.TransformerException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.setup.InboundWSSec;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

/**
 * A set of test-cases for signing and verifying SOAP requests, where the certificate used to
 * verify the signature is validated against a set of cert constraints.
 */
public class SignatureCertConstaintsTest extends AbstractTestBase {

    @Test
    public void testBSTSignature() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification: This should pass with a correct cert constraint check
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("wss40CA.jks"), "security".toCharArray());
            String certConstraint = ".*CN=Colm.*O=Apache.*";
            Pattern subjectDNPattern = Pattern.compile(certConstraint.trim());
            securityProperties.setSubjectCertConstraints(Collections.singletonList(subjectDNPattern));

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }

        //done signature; now test sig-verification: This should fail with an incorrect cert constraint check
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("wss40CA.jks"), "security".toCharArray());
            String certConstraint = ".*CN=Colm2.*O=Apache.*";
            Pattern subjectDNPattern = Pattern.compile(certConstraint.trim());
            securityProperties.setSubjectCertConstraints(Collections.singletonList(subjectDNPattern));

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties, false, true);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Expected failure on a incorrect cert constraint check");
            } catch (Exception ex) {
                String errorMessage = "The security token could not be authenticated or authorized";
                Assert.assertTrue(ex.getMessage().contains(errorMessage));
            }
        }
    }

    @Test
    public void testBSTSignaturePKIPath() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.USE_SINGLE_CERTIFICATE, "false");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification: This should pass with a correct cert constraint check
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("wss40CA.jks"), "security".toCharArray());
            String certConstraint = ".*CN=Colm.*O=Apache.*";
            Pattern subjectDNPattern = Pattern.compile(certConstraint.trim());
            securityProperties.setSubjectCertConstraints(Collections.singletonList(subjectDNPattern));

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }

        //done signature; now test sig-verification: This should fail with an incorrect cert constraint check
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("wss40CA.jks"), "security".toCharArray());
            String certConstraint = ".*CN=Colm2.*O=Apache.*";
            Pattern subjectDNPattern = Pattern.compile(certConstraint.trim());
            securityProperties.setSubjectCertConstraints(Collections.singletonList(subjectDNPattern));

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties, false, true);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Expected failure on a incorrect cert constraint check");
            } catch (Exception ex) {
                String errorMessage = "The security token could not be authenticated or authorized";
                Assert.assertTrue(ex.getMessage().contains(errorMessage));
            }
        }
    }

    @Override
    protected Map<String, Object> doOutboundSecurityWithWSS4J_1(
        InputStream sourceDocument, String action, final Properties properties
    ) throws WSSecurityException, TransformerException, IOException {
        CustomWSS4JHandler wss4JHandler = new CustomWSS4JHandler();
        final Map<String, Object> messageContext = getMessageContext(sourceDocument);
        messageContext.put(WSHandlerConstants.ACTION, action);
        messageContext.put(WSHandlerConstants.USER, "wss40");
        messageContext.put(WSHandlerConstants.SIG_KEY_ID, "DirectReference");

        Properties sigProperties = new Properties();
        sigProperties.setProperty("org.apache.wss4j.crypto.provider", "org.apache.wss4j.common.crypto.Merlin");
        sigProperties.setProperty("org.apache.wss4j.crypto.merlin.keystore.file", "wss40.jks");
        sigProperties.setProperty("org.apache.wss4j.crypto.merlin.keystore.password", "security");
        sigProperties.setProperty("org.apache.wss4j.crypto.merlin.keystore.alias", "wss40");
        wss4JHandler.setPassword(messageContext, "security");
        messageContext.put(WSHandlerConstants.SIG_PROP_REF_ID, "" + sigProperties.hashCode());
        messageContext.put("" + sigProperties.hashCode(), sigProperties);

        Enumeration<?> enumeration = properties.propertyNames();
        while (enumeration.hasMoreElements()) {
            String s = (String) enumeration.nextElement();
            messageContext.put(s, properties.get(s));
        }

        RequestData requestData = new RequestData();
        requestData.setMsgContext(messageContext);

        wss4JHandler.doSender(messageContext, requestData, true);

        return messageContext;
    }

}
