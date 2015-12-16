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
import java.util.Enumeration;
import java.util.Map;
import java.util.Properties;

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
 * This is a test for Certificate Revocation List checking. A message is signed and sent to the
 * receiver. If Certificate Revocation is enabled, then signature trust verification should
 * fail as the message has been signed by the private key corresponding to a revoked signature.
 *
 * Generate the client keypair, make a csr, sign it with the CA key
 *
 * keytool -genkey -validity 3650 -alias wss40rev -keyalg RSA -keystore wss40rev.jks
 * -dname "CN=Colm,OU=WSS4J,O=Apache,L=Dublin,ST=Leinster,C=IE"
 * keytool -certreq -alias wss40rev -keystore wss40rev.jks -file wss40rev.cer
 * openssl ca -config ca.config -policy policy_anything -days 3650 -out wss40rev.pem
 * -infiles wss40rev.cer
 * openssl x509 -outform DER -in wss40rev.pem -out wss40rev.crt
 *
 * Import the CA cert into wss40.jks and import the new signed certificate
 *
 * keytool -import -file wss40CA.crt -alias wss40CA -keystore wss40rev.jks
 * keytool -import -file wss40rev.crt -alias wss40rev -keystore wss40rev.jks
 *
 * Generate a Revocation list
 *
 * openssl ca -gencrl -keyfile wss40CAKey.pem -cert wss40CA.pem -out wss40CACRL.pem
 * -config ca.config -crldays 3650
 * openssl ca -revoke wss40rev.pem -keyfile wss40CAKey.pem -cert wss40CA.pem -config ca.config
 * openssl ca -gencrl -keyfile wss40CAKey.pem -cert wss40CA.pem -out wss40CACRL.pem
 * -config ca.config -crldays 3650
 */
public class SignatureCRLTest extends AbstractTestBase {

    /**
     * Test signing a SOAP message using a BST. Revocation is not enabled and so the test
     * should pass.
     * TODO Re-enable once CRL issue fixed
     */
    @Test
    @org.junit.Ignore
    public void testSignatureDirectReference() throws Exception {
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

        //done signature; now test sig-verification: This should pass as revocation is not enabled
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("wss40rev.jks"), "security".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }

        //done signature; now test sig-verification: This should fail as revocation is enabled
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setEnableRevocation(true);
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("wss40rev.jks"), "security".toCharArray());
            securityProperties.loadCRLCertStore(this.getClass().getClassLoader().getResource("wss40CACRL.pem"));
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Expected failure on a revocation check");
            } catch (Exception ex) {
                Assert.assertNotNull(ex.getCause());
                Assert.assertTrue(ex.getCause() instanceof WSSecurityException);
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
        messageContext.put(WSHandlerConstants.USER, "wss40rev");
        messageContext.put(WSHandlerConstants.SIG_KEY_ID, "DirectReference");

        Properties sigProperties = new Properties();
        sigProperties.setProperty("org.apache.wss4j.crypto.provider", "org.apache.wss4j.common.crypto.Merlin");
        sigProperties.setProperty("org.apache.wss4j.crypto.merlin.keystore.file", "wss40rev.jks");
        sigProperties.setProperty("org.apache.wss4j.crypto.merlin.keystore.password", "security");
        sigProperties.setProperty("org.apache.wss4j.crypto.merlin.keystore.alias", "wss40rev");
        sigProperties.setProperty("org.apache.wss4j.crypto.merlin.x509crl.file", "wss40CACRL.pem");
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
        requestData.setCallbackHandler(new WSS4JCallbackHandlerImpl());

        wss4JHandler.doSender(messageContext, requestData, true);

        return messageContext;
    }

}
