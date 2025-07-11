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
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.wss4j.api.dom.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.api.dom.WSConstants;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.apache.wss4j.api.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.api.stax.ext.WSSConstants;
import org.apache.wss4j.api.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.api.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.setup.OutboundWSSec;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.wss4j.stax.test.utils.XmlReaderToWriter;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.JCEAlgorithmMapper;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.impl.OutboundSecurityContextImpl;
import org.apache.xml.security.stax.impl.securityToken.GenericOutboundSecurityToken;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityToken.OutboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenProvider;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SignatureEncryptionTest extends AbstractTestBase {

    @Test
    public void testSignatureEncryptionOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.ENCRYPTION);
            actions.add(WSSConstants.TIMESTAMP);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            securityProperties.addSignaturePart(
                new SecurePart(new QName(WSSConstants.NS_WSU10, "Timestamp"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Element)
            );

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            baos = doOutboundSecurity(securityProperties, sourceDocument);

            documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION + " " + WSHandlerConstants.TIMESTAMP;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncryptionSymmetricOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION);
            actions.add(WSSConstants.TIMESTAMP);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);

            // Symmetric Key
            String keyAlgorithm =
                JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(WSSConstants.NS_XENC_AES128);
            KeyGenerator keyGen;
            try {
                keyGen = KeyGenerator.getInstance(keyAlgorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
            }
            int keyLength = JCEAlgorithmMapper.getKeyLengthFromURI(WSSConstants.NS_XENC_AES128);
            keyGen.init(keyLength);

            final Key symmetricKey = keyGen.generateKey();

            final String ekId = IDGenerator.generateID(null);

            final GenericOutboundSecurityToken encryptedKeySecurityToken =
                new GenericOutboundSecurityToken(ekId, WSSecurityTokenConstants.EncryptedKeyToken, symmetricKey);

            final SecurityTokenProvider<OutboundSecurityToken> encryptedKeySecurityTokenProvider =
                    new SecurityTokenProvider<OutboundSecurityToken>() {

                @Override
                public OutboundSecurityToken getSecurityToken() throws XMLSecurityException {
                    return encryptedKeySecurityToken;
                }

                @Override
                public String getId() {
                    return ekId;
                }
            };

            final OutboundSecurityContextImpl outboundSecurityContext = new OutboundSecurityContextImpl();
            outboundSecurityContext.putList(SecurityEvent.class, new ArrayList<SecurityEvent>());

            // Save Token on the security context
            outboundSecurityContext.registerSecurityTokenProvider(encryptedKeySecurityTokenProvider.getId(), encryptedKeySecurityTokenProvider);
            outboundSecurityContext.put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION, encryptedKeySecurityTokenProvider.getId());

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = new ByteArrayOutputStream();
            XMLStreamWriter xmlStreamWriter =
                wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), outboundSecurityContext);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPTION + " " + WSHandlerConstants.TIMESTAMP;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSignatureEncryptionSymmetricOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.ENCRYPTION);
            actions.add(WSSConstants.TIMESTAMP);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");

            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            securityProperties.setSignatureAlgorithm(WSSConstants.NS_XMLDSIG_HMACSHA1);
            securityProperties.setSignatureKeyIdentifier(
                WSSecurityTokenConstants.KeyIdentifier_EncryptedKey
            );

            securityProperties.addSignaturePart(
                new SecurePart(new QName(WSSConstants.NS_WSU10, "Timestamp"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Element)
            );

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);

            // Symmetric Key
            String keyAlgorithm =
                JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(WSSConstants.NS_XENC_AES128);
            KeyGenerator keyGen;
            try {
                keyGen = KeyGenerator.getInstance(keyAlgorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
            }
            int keyLength = JCEAlgorithmMapper.getKeyLengthFromURI(WSSConstants.NS_XENC_AES128);
            keyGen.init(keyLength);

            final Key symmetricKey = keyGen.generateKey();

            final String ekId = IDGenerator.generateID(null);

            final GenericOutboundSecurityToken encryptedKeySecurityToken =
                new GenericOutboundSecurityToken(ekId, WSSecurityTokenConstants.EncryptedKeyToken, symmetricKey);

            final SecurityTokenProvider<OutboundSecurityToken> encryptedKeySecurityTokenProvider =
                    new SecurityTokenProvider<OutboundSecurityToken>() {

                @Override
                public OutboundSecurityToken getSecurityToken() throws XMLSecurityException {
                    return encryptedKeySecurityToken;
                }

                @Override
                public String getId() {
                    return ekId;
                }
            };

            final OutboundSecurityContextImpl outboundSecurityContext = new OutboundSecurityContextImpl();
            outboundSecurityContext.putList(SecurityEvent.class, new ArrayList<SecurityEvent>());

            // Save Token on the security context
            outboundSecurityContext.registerSecurityTokenProvider(encryptedKeySecurityTokenProvider.getId(), encryptedKeySecurityTokenProvider);
            outboundSecurityContext.put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION, encryptedKeySecurityTokenProvider.getId());
            outboundSecurityContext.put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, encryptedKeySecurityTokenProvider.getId());

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = new ByteArrayOutputStream();
            XMLStreamWriter xmlStreamWriter =
                wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), outboundSecurityContext);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

            NodeList securityHeaderElement = document.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
            assertEquals(1, securityHeaderElement.getLength());
            NodeList childs = securityHeaderElement.item(0).getChildNodes();

            assertEquals(childs.getLength(), 4);
            assertEquals(childs.item(0).getLocalName(), "Timestamp");
            assertEquals(childs.item(1).getLocalName(), "EncryptedKey");
            assertEquals(childs.item(2).getLocalName(), "ReferenceList");
            assertEquals(childs.item(3).getLocalName(), "Signature");
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION + " " + WSHandlerConstants.TIMESTAMP;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncryptionSignatureSymmetricOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION);
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.TIMESTAMP);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");

            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            securityProperties.setSignatureAlgorithm(WSSConstants.NS_XMLDSIG_HMACSHA1);
            securityProperties.setSignatureKeyIdentifier(
                    WSSecurityTokenConstants.KeyIdentifier_EncryptedKey
            );

            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_WSU10, "Timestamp"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Element)
            );

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);

            // Symmetric Key
            String keyAlgorithm =
                    JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(WSSConstants.NS_XENC_AES128);
            KeyGenerator keyGen;
            try {
                keyGen = KeyGenerator.getInstance(keyAlgorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
            }
            int keyLength = JCEAlgorithmMapper.getKeyLengthFromURI(WSSConstants.NS_XENC_AES128);
            keyGen.init(keyLength);

            final Key symmetricKey = keyGen.generateKey();

            final String ekId = IDGenerator.generateID(null);

            final GenericOutboundSecurityToken encryptedKeySecurityToken =
                    new GenericOutboundSecurityToken(ekId, WSSecurityTokenConstants.EncryptedKeyToken, symmetricKey);

            final SecurityTokenProvider<OutboundSecurityToken> encryptedKeySecurityTokenProvider =
                    new SecurityTokenProvider<OutboundSecurityToken>() {

                        @Override
                        public OutboundSecurityToken getSecurityToken() throws XMLSecurityException {
                            return encryptedKeySecurityToken;
                        }

                        @Override
                        public String getId() {
                            return ekId;
                        }
                    };

            final OutboundSecurityContextImpl outboundSecurityContext = new OutboundSecurityContextImpl();
            outboundSecurityContext.putList(SecurityEvent.class, new ArrayList<SecurityEvent>());

            // Save Token on the security context
            outboundSecurityContext.registerSecurityTokenProvider(encryptedKeySecurityTokenProvider.getId(), encryptedKeySecurityTokenProvider);
            outboundSecurityContext.put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION, encryptedKeySecurityTokenProvider.getId());
            outboundSecurityContext.put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, encryptedKeySecurityTokenProvider.getId());

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = new ByteArrayOutputStream();
            XMLStreamWriter xmlStreamWriter =
                    wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), outboundSecurityContext);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

            NodeList securityHeaderElement = document.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
            assertEquals(1, securityHeaderElement.getLength());
            NodeList childs = securityHeaderElement.item(0).getChildNodes();

            assertEquals(childs.getLength(), 4);
            assertEquals(childs.item(0).getLocalName(), "Timestamp");
            assertEquals(childs.item(1).getLocalName(), "EncryptedKey");
            assertEquals(childs.item(2).getLocalName(), "Signature");
            assertEquals(childs.item(3).getLocalName(), "ReferenceList");
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPTION + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.TIMESTAMP;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncryptedDataTokenSecurityHeaderWithoutReferenceInbound() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            Document doc = documentBuilderFactory.newDocumentBuilder().parse(sourceDocument);

            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            WSSecSignature sign = new WSSecSignature(secHeader);
            sign.setUserInfo("transmitter", "default");
            sign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");

            sign.build( crypto);

            WSSecEncrypt builder = new WSSecEncrypt(secHeader);
            builder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
            builder.setUserInfo("receiver");

            KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128);
            SecretKey symmetricKey = keyGen.generateKey();
            builder.prepare(crypto, symmetricKey);

            WSEncryptionPart bst = new WSEncryptionPart("BinarySecurityToken", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "Element");
            WSEncryptionPart def = new WSEncryptionPart("definitions", "http://schemas.xmlsoap.org/wsdl/", "Element");
            List<WSEncryptionPart> encryptionParts = new ArrayList<>();
            encryptionParts.add(bst);
            encryptionParts.add(def);
            Element ref = builder.encryptForRef(null, encryptionParts, symmetricKey);
            ref.removeChild(ref.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "DataReference").item(0));
            builder.addExternalRefElement(ref);
            builder.prependToHeader();

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //no encrypted content
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
    }
}