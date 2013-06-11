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
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import javax.crypto.KeyGenerator;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.stax.WSSec;
import org.apache.wss4j.stax.ext.OutboundWSSec;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
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
import org.testng.annotations.Test;

public class SignatureEncryptionTest extends AbstractTestBase {

    @Test
    public void testSignatureEncryptionOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = 
                new WSSConstants.Action[]{WSSConstants.SIGNATURE, WSSConstants.ENCRYPT, WSSConstants.TIMESTAMP};
            securityProperties.setOutAction(actions);
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
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT + " " + WSHandlerConstants.TIMESTAMP;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }
    
    @Test
    public void testEncryptionSymmetricOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = 
                new WSSConstants.Action[]{WSSConstants.ENCRYPT, WSSConstants.TIMESTAMP};
            securityProperties.setOutAction(actions);
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
                wsSecOut.processOutMessage(baos, "UTF-8", outboundSecurityContext);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPT + " " + WSHandlerConstants.TIMESTAMP;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }
    
    @Test
    public void testSignatureEncryptionSymmetricOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = 
                new WSSConstants.Action[]{WSSConstants.SIGNATURE, WSSConstants.ENCRYPT, WSSConstants.TIMESTAMP};
            securityProperties.setOutAction(actions);
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
                wsSecOut.processOutMessage(baos, "UTF-8", outboundSecurityContext);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT + " " + WSHandlerConstants.TIMESTAMP;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

}
