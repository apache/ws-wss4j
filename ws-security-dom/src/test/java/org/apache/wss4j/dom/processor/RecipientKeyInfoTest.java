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

package org.apache.wss4j.dom.processor;

import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.common.crypto.KeystoreCallbackHandler;
import org.apache.wss4j.common.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.common.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.common.dom.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;


/**
 * This class tests correct handling of different RecipientKeyInfo contents in the AgreementMethod element.
 */
public class RecipientKeyInfoTest {
    private static final String X509SKI_XML = "<S12:Envelope xmlns:S12=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:eb=\"http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/\" xmlns:ebbp=\"http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0\" xmlns:ns5=\"http://www.w3.org/1999/xlink\">\n" +
            " <S12:Header>\n" +
            "  <wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" S12:mustUnderstand=\"true\">\n" +
            "   <xenc:EncryptedKey xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"EK-70fae604-dd7d-4eca-a6fb-f86cab628ef3\">\n" +
            "    <xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/>\n" +
            "    <ds:KeyInfo>\n" +
            "     <xenc:AgreementMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#ECDH-ES\">\n" +
            "      <xenc11:KeyDerivationMethod xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" Algorithm=\"http://www.w3.org/2009/xmlenc11#ConcatKDF\">\n" +
            "       <xenc11:ConcatKDFParams>\n" +
            "        <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n" +
            "       </xenc11:ConcatKDFParams>\n" +
            "      </xenc11:KeyDerivationMethod>\n" +
            "      <xenc:OriginatorKeyInfo>\n" +
            "       <ds:KeyValue>\n" +
            "        <dsig11:ECKeyValue xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\">\n" +
            "         <dsig11:NamedCurve URI=\"urn:oid:1.3.132.0.35\"/>\n" +
            "         <dsig11:PublicKey>BACyQlDSqpHbovJmv3FBpMghZoQYGgz80Odwq8Kg+Na0jlBDnoObQAiYP75CL0QFMEFUZln/fVk0OslooRXS3oSVIQASiRs0iVoxxSJmGLddnmh1Geyn0WVVVrWrAsq+DUpgF+o4uyKRdjNqT3zdRQKvXP9EXi5gTu1pM9rRXmjD4hu4Dg==</dsig11:PublicKey>\n" +
            "        </dsig11:ECKeyValue>\n" +
            "       </ds:KeyValue>\n" +
            "      </xenc:OriginatorKeyInfo>\n" +
            "      <xenc:RecipientKeyInfo>\n" +
            "       <ds:X509Data>\n" +
            "        <ds:X509SKI>pICAbVbWYkAOt/Whi7QgAInmstI=</ds:X509SKI>\n" +
            "       </ds:X509Data>\n" +
            "      </xenc:RecipientKeyInfo>\n" +
            "     </xenc:AgreementMethod>\n" +
            "    </ds:KeyInfo>\n" +
            "    <xenc:CipherData>\n" +
            "     <xenc:CipherValue>304N9yfr39kEasVxmqVzetY5BNxy65Jt</xenc:CipherValue>\n" +
            "    </xenc:CipherData>\n" +
            "    <xenc:ReferenceList>\n" +
            "     <xenc:DataReference URI=\"#ED-af4fd424-0178-4523-bd2c-f990ac78b6e5\"/>\n" +
            "    </xenc:ReferenceList>\n" +
            "   </xenc:EncryptedKey>\n" +
            "  </wsse:Security>\n" +
            " </S12:Header>\n" +
            " <S12:Body xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"id-103ba36e-7163-40bf-beba-cbb61d80f894\">\n" +
            "  <xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"ED-af4fd424-0178-4523-bd2c-f990ac78b6e5\" Type=\"http://www.w3.org/2001/04/xmlenc#Content\">\n" +
            "   <xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/>\n" +
            "   <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
            "    <wsse:SecurityTokenReference xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsse11=\"http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd\" wsse11:TokenType=\"http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey\">\n" +
            "     <wsse:Reference URI=\"#EK-802eb082-00c9-43da-a578-f68fe376b976\"/>\n" +
            "    </wsse:SecurityTokenReference>\n" +
            "   </ds:KeyInfo>\n" +
            "   <xenc:CipherData>\n" +
            "    <xenc:CipherValue>60eDOiVgEBqqPaLsrhyx+r1hYBoskcb69/iklYF3ISQAcGSBDRr9v5qMJRxwu9h3sij2plx4ac4GW+KXGwvI6VEEHoKSAsNWg+VwJEbnaIpfV5HaG/fdCz/vSEQ/XZNfkUwxlIP3iaywc2E6fPR/SA==</xenc:CipherValue>\n" +
            "   </xenc:CipherData>\n" +
            "  </xenc:EncryptedData>\n" + 
            " </S12:Body>\n" +
            "</S12:Envelope>";

    private static final String X509ISSUER_SERIAL_XML = "<S12:Envelope xmlns:S12=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:eb=\"http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/\" xmlns:ebbp=\"http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0\" xmlns:ns5=\"http://www.w3.org/1999/xlink\">\n" +
            " <S12:Header>\n" +
            "  <wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" S12:mustUnderstand=\"true\">\n" +
            "   <xenc:EncryptedKey xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"EK-70fae604-dd7d-4eca-a6fb-f86cab628ef3\">\n" +
            "    <xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/>\n" +
            "    <ds:KeyInfo>\n" +
            "     <xenc:AgreementMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#ECDH-ES\">\n" +
            "      <xenc11:KeyDerivationMethod xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" Algorithm=\"http://www.w3.org/2009/xmlenc11#ConcatKDF\">\n" +
            "       <xenc11:ConcatKDFParams>\n" +
            "        <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n" +
            "       </xenc11:ConcatKDFParams>\n" +
            "      </xenc11:KeyDerivationMethod>\n" +
            "      <xenc:OriginatorKeyInfo>\n" +
            "       <ds:KeyValue>\n" +
            "        <dsig11:ECKeyValue xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\">\n" +
            "         <dsig11:NamedCurve URI=\"urn:oid:1.3.132.0.35\"/>\n" +
            "         <dsig11:PublicKey>BACyQlDSqpHbovJmv3FBpMghZoQYGgz80Odwq8Kg+Na0jlBDnoObQAiYP75CL0QFMEFUZln/fVk0OslooRXS3oSVIQASiRs0iVoxxSJmGLddnmh1Geyn0WVVVrWrAsq+DUpgF+o4uyKRdjNqT3zdRQKvXP9EXi5gTu1pM9rRXmjD4hu4Dg==</dsig11:PublicKey>\n" +
            "        </dsig11:ECKeyValue>\n" +
            "       </ds:KeyValue>\n" +
            "      </xenc:OriginatorKeyInfo>\n" +
            "      <xenc:RecipientKeyInfo>\n" +
            "       <ds:X509Data>\n" +
            "        <ds:X509IssuerSerial>\n" +
            "         <ds:X509IssuerName>CN=issuer-ca, OU=eDeliveryAS4-2.0, OU=wss4j, O=apache, C=EU</ds:X509IssuerName>\n" +
            "         <ds:X509SerialNumber>12685121184234350225</ds:X509SerialNumber>\n" +
            "        </ds:X509IssuerSerial>\n" + 
            "       </ds:X509Data>\n" +
            "      </xenc:RecipientKeyInfo>\n" +
            "     </xenc:AgreementMethod>\n" +
            "    </ds:KeyInfo>\n" +
            "    <xenc:CipherData>\n" +
            "     <xenc:CipherValue>304N9yfr39kEasVxmqVzetY5BNxy65Jt</xenc:CipherValue>\n" +
            "    </xenc:CipherData>\n" +
            "    <xenc:ReferenceList>\n" +
            "     <xenc:DataReference URI=\"#ED-af4fd424-0178-4523-bd2c-f990ac78b6e5\"/>\n" +
            "    </xenc:ReferenceList>\n" +
            "   </xenc:EncryptedKey>\n" +
            "  </wsse:Security>\n" +
            " </S12:Header>\n" +
            " <S12:Body xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"id-103ba36e-7163-40bf-beba-cbb61d80f894\">\n" +
            "  <xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"ED-af4fd424-0178-4523-bd2c-f990ac78b6e5\" Type=\"http://www.w3.org/2001/04/xmlenc#Content\">\n" +
            "   <xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/>\n" +
            "   <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
            "    <wsse:SecurityTokenReference xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsse11=\"http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd\" wsse11:TokenType=\"http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey\">\n" +
            "     <wsse:Reference URI=\"#EK-802eb082-00c9-43da-a578-f68fe376b976\"/>\n" +
            "    </wsse:SecurityTokenReference>\n" +
            "   </ds:KeyInfo>\n" +
            "   <xenc:CipherData>\n" +
            "    <xenc:CipherValue>60eDOiVgEBqqPaLsrhyx+r1hYBoskcb69/iklYF3ISQAcGSBDRr9v5qMJRxwu9h3sij2plx4ac4GW+KXGwvI6VEEHoKSAsNWg+VwJEbnaIpfV5HaG/fdCz/vSEQ/XZNfkUwxlIP3iaywc2E6fPR/SA==</xenc:CipherValue>\n" +
            "   </xenc:CipherData>\n" +
            "  </xenc:EncryptedData>\n" +
            " </S12:Body>\n" +
            "</S12:Envelope>";


    private static final String X509CERT_XML = "<S12:Envelope xmlns:S12=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:eb=\"http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/\" xmlns:ebbp=\"http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0\" xmlns:ns5=\"http://www.w3.org/1999/xlink\">\n" +
            " <S12:Header>\n" +
            "  <wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" S12:mustUnderstand=\"true\">\n" +
            "   <xenc:EncryptedKey xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"EK-70fae604-dd7d-4eca-a6fb-f86cab628ef3\">\n" +
            "    <xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/>\n" +
            "    <ds:KeyInfo>\n" +
            "     <xenc:AgreementMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#ECDH-ES\">\n" +
            "      <xenc11:KeyDerivationMethod xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" Algorithm=\"http://www.w3.org/2009/xmlenc11#ConcatKDF\">\n" +
            "       <xenc11:ConcatKDFParams>\n" +
            "        <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n" +
            "       </xenc11:ConcatKDFParams>\n" +
            "      </xenc11:KeyDerivationMethod>\n" +
            "      <xenc:OriginatorKeyInfo>\n" +
            "       <ds:KeyValue>\n" +
            "        <dsig11:ECKeyValue xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\">\n" +
            "         <dsig11:NamedCurve URI=\"urn:oid:1.3.132.0.35\"/>\n" +
            "         <dsig11:PublicKey>BACyQlDSqpHbovJmv3FBpMghZoQYGgz80Odwq8Kg+Na0jlBDnoObQAiYP75CL0QFMEFUZln/fVk0OslooRXS3oSVIQASiRs0iVoxxSJmGLddnmh1Geyn0WVVVrWrAsq+DUpgF+o4uyKRdjNqT3zdRQKvXP9EXi5gTu1pM9rRXmjD4hu4Dg==</dsig11:PublicKey>\n" +
            "        </dsig11:ECKeyValue>\n" +
            "       </ds:KeyValue>\n" +
            "      </xenc:OriginatorKeyInfo>\n" +
            "      <xenc:RecipientKeyInfo>\n" +
            "       <ds:X509Data>\n" +
            "          <ds:X509Certificate>MIICJTCCAdegAwIBAgIJALAKmoInEiaRMAUGAytlcDBdMQswCQYDVQQGEwJFVTEPMA0GA1UEChMGYXBhY2hlMQ4wDAYDVQQLEwV3c3M0ajEZMBcGA1UECxMQZURlbGl2ZXJ5QVM0LTIuMDESMBAGA1UEAxMJaXNzdWVyLWNhMB4XDTI0MDEyMzA5MjU0OVoXDTM0MDEyMDA5MjU0OVowXTELMAkGA1UEBhMCRVUxDzANBgNVBAoTBmFwYWNoZTEOMAwGA1UECxMFd3NzNGoxGTAXBgNVBAsTEGVEZWxpdmVyeUFTNC0yLjAxEjAQBgNVBAMTCXNlY3A1MjFyMTCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEANDRUPByrM1VA/RFIk9yGLGTXlGWmHYgcdRswLyc/w0oTgG/+ScxavJQR1iGlnaFX47jH1kieDjWzNq4UQZmBViwAZgR7fnQUeyfuKmBG834JZSk/tTsYV9wmrH15yMP7ma5ywEf0xFFY6pFNxT/t7LQ1jKC1KFRWcOZy7rJGHXpcYDeo0IwQDAdBgNVHQ4EFgQUpICAbVbWYkAOt/Whi7QgAInmstIwHwYDVR0jBBgwFoAUaFQmrZknhkwmaSxDEbij4XEfWHUwBQYDK2VwA0EAvgmA7/omtxY/B9G80tJLghjLabffm4C/C2ze52xyG6TAg2IgWR2yyXpNTaulRe4eXYodJ9/YISO3cty0+LVWAQ==</ds:X509Certificate>" +
            "       </ds:X509Data>\n" +
            "      </xenc:RecipientKeyInfo>\n" +
            "     </xenc:AgreementMethod>\n" +
            "    </ds:KeyInfo>\n" +
            "    <xenc:CipherData>\n" +
            "     <xenc:CipherValue>304N9yfr39kEasVxmqVzetY5BNxy65Jt</xenc:CipherValue>\n" +
            "    </xenc:CipherData>\n" +
            "    <xenc:ReferenceList>\n" +
            "     <xenc:DataReference URI=\"#ED-af4fd424-0178-4523-bd2c-f990ac78b6e5\"/>\n" +
            "    </xenc:ReferenceList>\n" +
            "   </xenc:EncryptedKey>\n" +
            "  </wsse:Security>\n" +
            " </S12:Header>\n" +
            " <S12:Body xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"id-103ba36e-7163-40bf-beba-cbb61d80f894\">\n" +
            "  <xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"ED-af4fd424-0178-4523-bd2c-f990ac78b6e5\" Type=\"http://www.w3.org/2001/04/xmlenc#Content\">\n" +
            "   <xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/>\n" +
            "   <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
            "    <wsse:SecurityTokenReference xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsse11=\"http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd\" wsse11:TokenType=\"http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey\">\n" +
            "     <wsse:Reference URI=\"#EK-802eb082-00c9-43da-a578-f68fe376b976\"/>\n" +
            "    </wsse:SecurityTokenReference>\n" +
            "   </ds:KeyInfo>\n" +
            "   <xenc:CipherData>\n" +
            "    <xenc:CipherValue>60eDOiVgEBqqPaLsrhyx+r1hYBoskcb69/iklYF3ISQAcGSBDRr9v5qMJRxwu9h3sij2plx4ac4GW+KXGwvI6VEEHoKSAsNWg+VwJEbnaIpfV5HaG/fdCz/vSEQ/XZNfkUwxlIP3iaywc2E6fPR/SA==</xenc:CipherValue>\n" +
            "   </xenc:CipherData>\n" +
            "  </xenc:EncryptedData>\n" +
            " </S12:Body>\n" +
            "</S12:Envelope>";

    private static final String ECKEY_VALUE_XML = "<S12:Envelope xmlns:S12=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:eb=\"http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/\" xmlns:ebbp=\"http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0\" xmlns:ns5=\"http://www.w3.org/1999/xlink\">\n" +
            " <S12:Header>\n" +
            "  <wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" S12:mustUnderstand=\"true\">\n" +
            "   <xenc:EncryptedKey xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"EK-70fae604-dd7d-4eca-a6fb-f86cab628ef3\">\n" +
            "    <xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/>\n" +
            "    <ds:KeyInfo>\n" +
            "     <xenc:AgreementMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#ECDH-ES\">\n" +
            "      <xenc11:KeyDerivationMethod xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" Algorithm=\"http://www.w3.org/2009/xmlenc11#ConcatKDF\">\n" +
            "       <xenc11:ConcatKDFParams>\n" +
            "        <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n" +
            "       </xenc11:ConcatKDFParams>\n" +
            "      </xenc11:KeyDerivationMethod>\n" +
            "      <xenc:OriginatorKeyInfo>\n" +
            "       <ds:KeyValue>\n" +
            "        <dsig11:ECKeyValue xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\">\n" +
            "         <dsig11:NamedCurve URI=\"urn:oid:1.3.132.0.35\"/>\n" +
            "         <dsig11:PublicKey>BACyQlDSqpHbovJmv3FBpMghZoQYGgz80Odwq8Kg+Na0jlBDnoObQAiYP75CL0QFMEFUZln/fVk0OslooRXS3oSVIQASiRs0iVoxxSJmGLddnmh1Geyn0WVVVrWrAsq+DUpgF+o4uyKRdjNqT3zdRQKvXP9EXi5gTu1pM9rRXmjD4hu4Dg==</dsig11:PublicKey>\n" +
            "        </dsig11:ECKeyValue>\n" +
            "       </ds:KeyValue>\n" +
            "      </xenc:OriginatorKeyInfo>\n" +
            "      <xenc:RecipientKeyInfo>\n" +
            "       <ds:KeyValue>\n" +
            "        <dsig11:ECKeyValue xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\">\n" +
            "         <dsig11:NamedCurve URI=\"urn:oid:1.3.132.0.35\"/>\n" +
            "         <dsig11:PublicKey>BADQ0VDwcqzNVQP0RSJPchixk15Rlph2IHHUbMC8nP8NKE4Bv/knMWryUEdYhpZ2hV+O4x9ZIng41szauFEGZgVYsAGYEe350FHsn7ipgRvN+CWUpP7U7GFfcJqx9ecjD+5mucsBH9MRRWOqRTcU/7ey0NYygtShUVnDmcu6yRh16XGA3g==</dsig11:PublicKey>\n" +
            "        </dsig11:ECKeyValue>\n" +
            "       </ds:KeyValue>\n" +
            "      </xenc:RecipientKeyInfo>\n" +
            "     </xenc:AgreementMethod>\n" +
            "    </ds:KeyInfo>\n" +
            "    <xenc:CipherData>\n" +
            "     <xenc:CipherValue>304N9yfr39kEasVxmqVzetY5BNxy65Jt</xenc:CipherValue>\n" +
            "    </xenc:CipherData>\n" +
            "    <xenc:ReferenceList>\n" +
            "     <xenc:DataReference URI=\"#ED-af4fd424-0178-4523-bd2c-f990ac78b6e5\"/>\n" +
            "    </xenc:ReferenceList>\n" +
            "   </xenc:EncryptedKey>\n" +
            "  </wsse:Security>\n" +
            " </S12:Header>\n" +
            " <S12:Body xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"id-103ba36e-7163-40bf-beba-cbb61d80f894\">\n" +
            "  <xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"ED-af4fd424-0178-4523-bd2c-f990ac78b6e5\" Type=\"http://www.w3.org/2001/04/xmlenc#Content\">\n" +
            "   <xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/>\n" +
            "   <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
            "    <wsse:SecurityTokenReference xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsse11=\"http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd\" wsse11:TokenType=\"http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey\">\n" +
            "     <wsse:Reference URI=\"#EK-802eb082-00c9-43da-a578-f68fe376b976\"/>\n" +
            "    </wsse:SecurityTokenReference>\n" +
            "   </ds:KeyInfo>\n" +
            "   <xenc:CipherData>\n" +
            "    <xenc:CipherValue>60eDOiVgEBqqPaLsrhyx+r1hYBoskcb69/iklYF3ISQAcGSBDRr9v5qMJRxwu9h3sij2plx4ac4GW+KXGwvI6VEEHoKSAsNWg+VwJEbnaIpfV5HaG/fdCz/vSEQ/XZNfkUwxlIP3iaywc2E6fPR/SA==</xenc:CipherValue>\n" +
            "   </xenc:CipherData>\n" +
            "  </xenc:EncryptedData>\n" +
            " </S12:Body>\n" +
            "</S12:Envelope>";


    public RecipientKeyInfoTest() {
        WSSConfig.init();
    }

    @Test
    public void testECDHEncryptionWithX509SKI() throws Exception {
        Document document = SOAPUtil.toSOAPPart(X509SKI_XML);

        final WSSecurityEngine secEngine = new WSSecurityEngine();
        final RequestData requestData = new RequestData();

        Crypto encCrypto = CryptoFactory.getInstance("wss-ecdh.properties");
        requestData.setDecCrypto(encCrypto);
        requestData.setCallbackHandler(new KeystoreCallbackHandler());
        requestData.setIgnoredBSPRules(List.of(BSPRule.R5426));
        WSHandlerResult wsHandlerResults = secEngine.processSecurityHeader(document, requestData);
        assertEquals(1, wsHandlerResults.getResults().size());
        WSSecurityEngineResult result = wsHandlerResults.getResults().get(0);
        assertArrayEquals(new byte[] {35, 14, -124, -105, -120, -7, -92, -63, -59, -72, -52, 121, 69, -83, 42, -89}, (byte[])result.get(WSSecurityEngineResult.TAG_SECRET));
    }

    @Test
    public void testECDHEncryptionWithX509IssuerSerial() throws Exception {
        Document document = SOAPUtil.toSOAPPart(X509ISSUER_SERIAL_XML);

        final WSSecurityEngine secEngine = new WSSecurityEngine();
        final RequestData requestData = new RequestData();

        Crypto encCrypto = CryptoFactory.getInstance("wss-ecdh.properties");
        requestData.setDecCrypto(encCrypto);
        requestData.setCallbackHandler(new KeystoreCallbackHandler());
        requestData.setIgnoredBSPRules(List.of(BSPRule.R5426));
        WSHandlerResult wsHandlerResults = secEngine.processSecurityHeader(document, requestData);
        assertEquals(1, wsHandlerResults.getResults().size());
        WSSecurityEngineResult result = wsHandlerResults.getResults().get(0);
        assertArrayEquals(new byte[] {35, 14, -124, -105, -120, -7, -92, -63, -59, -72, -52, 121, 69, -83, 42, -89}, (byte[])result.get(WSSecurityEngineResult.TAG_SECRET));
    }

    @Test
    public void testECDHEncryptionWithX509certificate() throws Exception {
        Document document = SOAPUtil.toSOAPPart(X509CERT_XML);

        final WSSecurityEngine secEngine = new WSSecurityEngine();
        final RequestData requestData = new RequestData();

        Crypto encCrypto = CryptoFactory.getInstance("wss-ecdh.properties");
        requestData.setDecCrypto(encCrypto);
        requestData.setCallbackHandler(new KeystoreCallbackHandler());
        requestData.setIgnoredBSPRules(List.of(BSPRule.R5426));
        WSHandlerResult wsHandlerResults = secEngine.processSecurityHeader(document, requestData);
        assertEquals(1, wsHandlerResults.getResults().size());
        WSSecurityEngineResult result = wsHandlerResults.getResults().get(0);
        assertArrayEquals(new byte[] {35, 14, -124, -105, -120, -7, -92, -63, -59, -72, -52, 121, 69, -83, 42, -89}, (byte[])result.get(WSSecurityEngineResult.TAG_SECRET));
    }

    @Test
    public void testECDHEncryptionWithECKeyValue() throws Exception {
        Document document = SOAPUtil.toSOAPPart(ECKEY_VALUE_XML);

        final WSSecurityEngine secEngine = new WSSecurityEngine();
        final RequestData requestData = new RequestData();

        Crypto encCrypto = CryptoFactory.getInstance("wss-ecdh.properties");
        requestData.setDecCrypto(encCrypto);
        requestData.setCallbackHandler(new KeystoreCallbackHandler());
        requestData.setIgnoredBSPRules(List.of(BSPRule.R5426));
        WSHandlerResult wsHandlerResults = secEngine.processSecurityHeader(document, requestData);
        assertEquals(1, wsHandlerResults.getResults().size());
        WSSecurityEngineResult result = wsHandlerResults.getResults().get(0);
        assertArrayEquals(new byte[] {35, 14, -124, -105, -120, -7, -92, -63, -59, -72, -52, 121, 69, -83, 42, -89}, (byte[])result.get(WSSecurityEngineResult.TAG_SECRET));
    }
}