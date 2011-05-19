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
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.message.*;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.swssf.WSSec;
import org.swssf.ext.Constants;
import org.swssf.ext.InboundWSSec;
import org.swssf.ext.OutboundWSSec;
import org.swssf.ext.SecurityProperties;
import org.swssf.securityEvent.SecurityEvent;
import org.swssf.test.utils.SOAPUtil;
import org.swssf.test.utils.StAX2DOM;
import org.swssf.test.utils.XmlReaderToWriter;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

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
    public void testEncryptionDecryptionTRIPLEDESOutbound() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT_WITH_DERIVED_KEY};
            securityProperties.setOutAction(actions);
            byte[] secret = new byte[128 / 8];
            Constants.secureRandom.nextBytes(secret);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(secret);
            securityProperties.setCallbackHandler(callbackHandler);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");
            securityProperties.setEncryptionKeyIdentifierType(Constants.KeyIdentifierType.THUMBPRINT_IDENTIFIER);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_soap11_Body.getLocalPart());
        }
        {
            String action = WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncryptionDecryptionTRIPLEDESInbound() throws Exception {

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
    public void testEncryptionDecryptionAES128Outbound() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT_WITH_DERIVED_KEY};
            securityProperties.setOutAction(actions);
            byte[] secret = new byte[128 / 8];
            Constants.secureRandom.nextBytes(secret);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(secret);
            securityProperties.setCallbackHandler(callbackHandler);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes128-cbc");
            securityProperties.setEncryptionKeyIdentifierType(Constants.KeyIdentifierType.THUMBPRINT_IDENTIFIER);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedData.getNamespaceURI(), Constants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_soap11_Body.getLocalPart());
        }
        {
            String action = WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncryptionDecryptionAES128Inbound() throws Exception {

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
    public void testSignatureOutbound() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.SIGNATURE_WITH_DERIVED_KEY};
            securityProperties.setOutAction(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            securityProperties.setCallbackHandler(callbackHandler);
            securityProperties.setEncryptionKeyIdentifierType(Constants.KeyIdentifierType.THUMBPRINT_IDENTIFIER);
            securityProperties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1");
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setDerivedKeyTokenReference(Constants.DerivedKeyTokenReference.EncryptedKey);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("receiver");

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());
        }
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSignatureInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader();
            secHeader.insertSecurityHeader(doc);

            //EncryptedKey
            WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey();
            encrKeyBuilder.setUserInfo("receiver");
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
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
    }

    @Test
    public void testSignatureThumbprintSHA1Outbound() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.SIGNATURE_WITH_DERIVED_KEY};
            securityProperties.setOutAction(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            securityProperties.setCallbackHandler(callbackHandler);
            securityProperties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1");
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("receiver");
            securityProperties.setDerivedKeyTokenReference(Constants.DerivedKeyTokenReference.DirectReference);
            securityProperties.setDerivedKeyKeyIdentifierType(Constants.KeyIdentifierType.THUMBPRINT_IDENTIFIER);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_wsc0502_SecurityContextToken.getNamespaceURI(), Constants.TAG_wsc0502_SecurityContextToken.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
            nodeList = document.getElementsByTagNameNS(Constants.TAG_wsc0502_DerivedKeyToken.getNamespaceURI(), Constants.TAG_wsc0502_DerivedKeyToken.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_KeyIdentifier.getNamespaceURI(), Constants.TAG_wsse_KeyIdentifier.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Attr attr = (Attr) nodeList.item(0).getAttributes().getNamedItem(Constants.ATT_NULL_ValueType.getLocalPart());
            Assert.assertEquals(attr.getValue(), Constants.NS_THUMBPRINT);
            nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSignatureThumbprintSHA1Inbound() throws Exception {

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
    public void testSignatureSKIOutbound() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.SIGNATURE_WITH_DERIVED_KEY};
            securityProperties.setOutAction(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            securityProperties.setCallbackHandler(callbackHandler);
            securityProperties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1");
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("receiver");
            securityProperties.setDerivedKeyTokenReference(Constants.DerivedKeyTokenReference.DirectReference);
            securityProperties.setDerivedKeyKeyIdentifierType(Constants.KeyIdentifierType.SKI_KEY_IDENTIFIER);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_wsc0502_SecurityContextToken.getNamespaceURI(), Constants.TAG_wsc0502_SecurityContextToken.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
            nodeList = document.getElementsByTagNameNS(Constants.TAG_wsc0502_DerivedKeyToken.getNamespaceURI(), Constants.TAG_wsc0502_DerivedKeyToken.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_KeyIdentifier.getNamespaceURI(), Constants.TAG_wsse_KeyIdentifier.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Attr attr = (Attr) nodeList.item(0).getAttributes().getNamedItem(Constants.ATT_NULL_ValueType.getLocalPart());
            Assert.assertEquals(attr.getValue(), Constants.NS_X509SubjectKeyIdentifier);
            nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSignatureSKIInbound() throws Exception {

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
    public void testSignatureEncryptOutbound() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.SIGNATURE_WITH_DERIVED_KEY, Constants.Action.ENCRYPT_WITH_DERIVED_KEY};
            securityProperties.setOutAction(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            securityProperties.setCallbackHandler(callbackHandler);
            securityProperties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1");
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("receiver");
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(Constants.KeyIdentifierType.THUMBPRINT_IDENTIFIER);
            securityProperties.setDerivedKeyTokenReference(Constants.DerivedKeyTokenReference.EncryptedKey);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_wsc0502_SecurityContextToken.getNamespaceURI(), Constants.TAG_wsc0502_SecurityContextToken.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            nodeList = document.getElementsByTagNameNS(Constants.TAG_wsc0502_DerivedKeyToken.getNamespaceURI(), Constants.TAG_wsc0502_DerivedKeyToken.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_KeyIdentifier.getNamespaceURI(), Constants.TAG_wsse_KeyIdentifier.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Attr attr = (Attr) nodeList.item(0).getAttributes().getNamedItem(Constants.ATT_NULL_ValueType.getLocalPart());
            Assert.assertEquals(attr.getValue(), Constants.NS_THUMBPRINT);
            attr = (Attr) nodeList.item(1).getAttributes().getNamedItem(Constants.ATT_NULL_ValueType.getLocalPart());
            Assert.assertEquals(attr.getValue(), Constants.NS_THUMBPRINT);
            nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSignatureEncryptInbound() throws Exception {

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
    public void testEncryptSignatureOutbound() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SecurityProperties securityProperties = new SecurityProperties();
            Constants.Action[] actions = new Constants.Action[]{Constants.Action.ENCRYPT_WITH_DERIVED_KEY, Constants.Action.SIGNATURE_WITH_DERIVED_KEY};
            securityProperties.setOutAction(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            securityProperties.setCallbackHandler(callbackHandler);
            securityProperties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1");
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("receiver");
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(Constants.KeyIdentifierType.THUMBPRINT_IDENTIFIER);
            securityProperties.setDerivedKeyTokenReference(Constants.DerivedKeyTokenReference.EncryptedKey);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), Constants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(Constants.TAG_wsc0502_SecurityContextToken.getNamespaceURI(), Constants.TAG_wsc0502_SecurityContextToken.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
            nodeList = document.getElementsByTagNameNS(Constants.TAG_xenc_EncryptedKey.getNamespaceURI(), Constants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            nodeList = document.getElementsByTagNameNS(Constants.TAG_wsc0502_DerivedKeyToken.getNamespaceURI(), Constants.TAG_wsc0502_DerivedKeyToken.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            nodeList = document.getElementsByTagNameNS(Constants.TAG_wsse_KeyIdentifier.getNamespaceURI(), Constants.TAG_wsse_KeyIdentifier.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Attr attr = (Attr) nodeList.item(0).getAttributes().getNamedItem(Constants.ATT_NULL_ValueType.getLocalPart());
            Assert.assertEquals(attr.getValue(), Constants.NS_THUMBPRINT);
            attr = (Attr) nodeList.item(1).getAttributes().getNamedItem(Constants.ATT_NULL_ValueType.getLocalPart());
            Assert.assertEquals(attr.getValue(), Constants.NS_THUMBPRINT);
            nodeList = document.getElementsByTagNameNS(Constants.TAG_dsig_Signature.getNamespaceURI(), Constants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
        {
            String action = WSHandlerConstants.ENCRYPT + " " + WSHandlerConstants.SIGNATURE;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncryptSignatureInbound() throws Exception {

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
