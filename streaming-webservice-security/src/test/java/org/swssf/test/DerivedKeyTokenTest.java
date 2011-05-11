/*
 * Copyright 1996-2011 itServe AG. All rights reserved.
 *
 * This software is the proprietary information of itServe AG
 * Bern Switzerland. Use is subject to license terms.
 *
 */
package org.swssf.test;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.message.*;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.swssf.WSSec;
import org.swssf.ext.Constants;
import org.swssf.ext.InboundWSSec;
import org.swssf.ext.SecurityProperties;
import org.swssf.test.utils.SOAPUtil;
import org.swssf.test.utils.StAX2DOM;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.X509Certificate;

/**
 * @author $Author: $
 * @version $Revision: $ $Date: $
 */
public class DerivedKeyTokenTest extends AbstractTestBase {

    @BeforeClass
    public void setUp() throws Exception {
        WSSConfig.init();
    }

    @Test
    public void testEncryptionDecryptionTRIPLEDES() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader();
            secHeader.insertSecurityHeader(doc);

            WSSecSecurityContextToken sctBuilder = new WSSecSecurityContextToken();
            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");
            sctBuilder.prepare(doc, crypto);

            //EncryptedKey
            WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey();
            encrKeyBuilder.setUserInfo("receiver");
            encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
            encrKeyBuilder.prepare(doc, crypto);

            //Key information from the EncryptedKey
            byte[] ek = encrKeyBuilder.getEphemeralKey();
            String tokenIdentifier = encrKeyBuilder.getId();

            //Derived key encryption
            WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
            encrBuilder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
            encrBuilder.setExternalKey(ek, tokenIdentifier);
            encrBuilder.build(doc, secHeader);

            encrKeyBuilder.prependToHeader(secHeader);
            encrKeyBuilder.prependBSTElementToHeader(secHeader);

            NodeList nodeList = doc.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncryptionDecryptionAES128() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader();
            secHeader.insertSecurityHeader(doc);

            WSSecSecurityContextToken sctBuilder = new WSSecSecurityContextToken();
            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");
            sctBuilder.prepare(doc, crypto);

            //EncryptedKey
            WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey();
            encrKeyBuilder.setUserInfo("receiver");
            encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
            encrKeyBuilder.prepare(doc, crypto);

            //Key information from the EncryptedKey
            byte[] ek = encrKeyBuilder.getEphemeralKey();
            String tokenIdentifier = encrKeyBuilder.getId();

            //Derived key encryption
            WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
            encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
            encrBuilder.setExternalKey(ek, tokenIdentifier);
            encrBuilder.build(doc, secHeader);

            encrKeyBuilder.prependToHeader(secHeader);
            encrKeyBuilder.prependBSTElementToHeader(secHeader);

            NodeList nodeList = doc.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testSignature() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader();
            secHeader.insertSecurityHeader(doc);

            //EncryptedKey
            WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey();
            encrKeyBuilder.setUserInfo("transmitter");
            encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");
            encrKeyBuilder.prepare(doc, crypto);

            //Key information from the EncryptedKey
            byte[] ek = encrKeyBuilder.getEphemeralKey();
            String tokenIdentifier = encrKeyBuilder.getId();

            //Derived key encryption
            WSSecDKSign sigBuilder = new WSSecDKSign();
            sigBuilder.setExternalKey(ek, tokenIdentifier);
            sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
            sigBuilder.build(doc, secHeader);

            encrKeyBuilder.prependToHeader(secHeader);
            encrKeyBuilder.prependBSTElementToHeader(secHeader);

            NodeList nodeList = doc.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
    }

    @Test
    public void testSignatureThumbprintSHA1() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader();
            secHeader.insertSecurityHeader(doc);

            SecurityTokenReference secToken = new SecurityTokenReference(doc);
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
            cryptoType.setAlias("transmitter");
            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");
            X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
            secToken.setKeyIdentifierThumb(certs[0]);

            WSSecDKSign sigBuilder = new WSSecDKSign();
            java.security.Key key = crypto.getPrivateKey("transmitter", "default");
            sigBuilder.setExternalKey(key.getEncoded(), secToken.getElement());
            sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
            sigBuilder.build(doc, secHeader);

            sigBuilder.prependDKElementToHeader(secHeader);

            NodeList nodeList = doc.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
    }

    @Test
    public void testSignatureSKI() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader();
            secHeader.insertSecurityHeader(doc);

            SecurityTokenReference secToken = new SecurityTokenReference(doc);
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
            cryptoType.setAlias("transmitter");
            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");
            X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
            secToken.setKeyIdentifierSKI(certs[0], crypto);

            WSSecDKSign sigBuilder = new WSSecDKSign();
            java.security.Key key = crypto.getPrivateKey("transmitter", "default");
            sigBuilder.setExternalKey(key.getEncoded(), secToken.getElement());
            sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
            sigBuilder.build(doc, secHeader);

            sigBuilder.prependDKElementToHeader(secHeader);

            NodeList nodeList = doc.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
    }

    @Test
    public void testSignatureEncrypt() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader();
            secHeader.insertSecurityHeader(doc);

            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");

            //EncryptedKey
            WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey();
            encrKeyBuilder.setUserInfo("receiver");
            encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
            encrKeyBuilder.prepare(doc, crypto);

            //Key information from the EncryptedKey
            byte[] ek = encrKeyBuilder.getEphemeralKey();
            String tokenIdentifier = encrKeyBuilder.getId();

            //Derived key encryption
            WSSecDKSign sigBuilder = new WSSecDKSign();
            sigBuilder.setExternalKey(ek, tokenIdentifier);
            sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
            Document signedDoc = sigBuilder.build(doc, secHeader);

            //Derived key signature
            WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
            encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
            encrBuilder.setExternalKey(ek, tokenIdentifier);
            encrBuilder.build(signedDoc, secHeader);

            encrKeyBuilder.prependToHeader(secHeader);
            encrKeyBuilder.prependBSTElementToHeader(secHeader);

            NodeList nodeList = doc.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = doc.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncryptSignature() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader();
            secHeader.insertSecurityHeader(doc);

            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");

            //EncryptedKey
            WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey();
            encrKeyBuilder.setUserInfo("receiver");
            encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
            encrKeyBuilder.prepare(doc, crypto);

            //Key information from the EncryptedKey
            byte[] ek = encrKeyBuilder.getEphemeralKey();
            String tokenIdentifier = encrKeyBuilder.getId();

            //Derived key signature
            WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
            encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
            encrBuilder.setExternalKey(ek, tokenIdentifier);
            encrBuilder.build(doc, secHeader);

            //Derived key encryption
            WSSecDKSign sigBuilder = new WSSecDKSign();
            sigBuilder.setExternalKey(ek, tokenIdentifier);
            sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
            sigBuilder.build(doc, secHeader);

            encrKeyBuilder.prependToHeader(secHeader);
            encrKeyBuilder.prependBSTElementToHeader(secHeader);

            NodeList nodeList = doc.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = doc.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            SecurityProperties securityProperties = new SecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }
}
