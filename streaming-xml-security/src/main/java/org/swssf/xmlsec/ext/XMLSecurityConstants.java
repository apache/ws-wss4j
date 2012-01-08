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
package org.swssf.xmlsec.ext;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * XMLSecurityConstants for global use
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class XMLSecurityConstants {

    public static final SecureRandom secureRandom;
    //todo jaxbContext pool?
    private static JAXBContext jaxbContext;

    static {
        try {
            secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(System.currentTimeMillis());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        try {
            //todo schema validation?
            setJaxbContext(JAXBContext.newInstance("org.swssf.binding.xmlenc:org.swssf.binding.xmldsig:org.swssf.binding.excc14n"));
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        }
    }

    protected XMLSecurityConstants() {
    }

    protected static synchronized void setJaxbContext(JAXBContext jaxbContext) {
        XMLSecurityConstants.jaxbContext = jaxbContext;
    }

    public static JAXBContext getJaxbContext() {
        return jaxbContext;
    }

    public enum Phase {
        PREPROCESSING,
        PROCESSING,
        POSTPROCESSING,
    }

    public static final String XMLINPUTFACTORY = "XMLInputFactory";
    public static final XMLEventFactory XMLEVENTFACTORY = XMLEventFactory.newFactory();

    public static final String NS_XML = "http://www.w3.org/2000/xmlns/";
    public static final String NS_XMLENC = "http://www.w3.org/2001/04/xmlenc#";
    public static final String NS_DSIG = "http://www.w3.org/2000/09/xmldsig#";
    public static final String NS_WSSE11 = "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd";

    public static final String PREFIX_XENC = "xenc";
    public static final QName TAG_xenc_EncryptedKey = new QName(NS_XMLENC, "EncryptedKey", PREFIX_XENC);
    public static final QName ATT_NULL_Id = new QName(null, "Id");
    public static final QName ATT_NULL_Type = new QName(null, "Type");
    public static final QName ATT_NULL_MimeType = new QName(null, "MimeType");
    public static final QName ATT_NULL_Encoding = new QName(null, "Encoding");

    public static final QName TAG_xenc_EncryptionMethod = new QName(NS_XMLENC, "EncryptionMethod", PREFIX_XENC);
    public static final QName ATT_NULL_Algorithm = new QName(null, "Algorithm");

    public static final String PREFIX_DSIG = "dsig";
    public static final QName TAG_dsig_KeyInfo = new QName(NS_DSIG, "KeyInfo", PREFIX_DSIG);

    public static final QName TAG_xenc_EncryptionProperties = new QName(NS_XMLENC, "EncryptionProperties", PREFIX_XENC);
    public static final QName TAG_xenc_CipherData = new QName(NS_XMLENC, "CipherData", PREFIX_XENC);
    public static final QName TAG_xenc_CipherValue = new QName(NS_XMLENC, "CipherValue", PREFIX_XENC);
    public static final QName TAG_xenc_ReferenceList = new QName(NS_XMLENC, "ReferenceList", PREFIX_XENC);
    public static final QName TAG_xenc_DataReference = new QName(NS_XMLENC, "DataReference", PREFIX_XENC);
    public static final QName ATT_NULL_URI = new QName(null, "URI");

    public static final QName TAG_xenc_EncryptedData = new QName(NS_XMLENC, "EncryptedData", PREFIX_XENC);

    public static final String PREFIX_WSSE11 = "wsse11";
    public static final QName TAG_wsse11_EncryptedHeader = new QName(NS_WSSE11, "EncryptedHeader", PREFIX_WSSE11);

    public static final QName TAG_dsig_Signature = new QName(NS_DSIG, "Signature", PREFIX_DSIG);
    public static final QName TAG_dsig_SignedInfo = new QName(NS_DSIG, "SignedInfo", PREFIX_DSIG);
    public static final QName TAG_dsig_CanonicalizationMethod = new QName(NS_DSIG, "CanonicalizationMethod", PREFIX_DSIG);
    public static final QName TAG_dsig_SignatureMethod = new QName(NS_DSIG, "SignatureMethod", PREFIX_DSIG);
    public static final QName TAG_dsig_Reference = new QName(NS_DSIG, "Reference", PREFIX_DSIG);
    public static final QName TAG_dsig_Transforms = new QName(NS_DSIG, "Transforms", PREFIX_DSIG);
    public static final QName TAG_dsig_Transform = new QName(NS_DSIG, "Transform", PREFIX_DSIG);
    public static final QName TAG_dsig_DigestMethod = new QName(NS_DSIG, "DigestMethod", PREFIX_DSIG);
    public static final QName TAG_dsig_DigestValue = new QName(NS_DSIG, "DigestValue", PREFIX_DSIG);
    public static final QName TAG_dsig_SignatureValue = new QName(NS_DSIG, "SignatureValue", PREFIX_DSIG);

    public static final QName TAG_dsig_X509Data = new QName(NS_DSIG, "X509Data", PREFIX_DSIG);
    public static final QName TAG_dsig_X509IssuerSerial = new QName(NS_DSIG, "X509IssuerSerial", PREFIX_DSIG);
    public static final QName TAG_dsig_X509IssuerName = new QName(NS_DSIG, "X509IssuerName", PREFIX_DSIG);
    public static final QName TAG_dsig_X509SerialNumber = new QName(NS_DSIG, "X509SerialNumber", PREFIX_DSIG);

    public static final String NS_C14N_EXCL = "http://www.w3.org/2001/10/xml-exc-c14n#";
    public static final String PREFIX_C14N_EXCL = "c14nEx";
    public static final QName ATT_NULL_PrefixList = new QName(null, "PrefixList");
    public static final QName TAG_c14nExcl_InclusiveNamespaces = new QName(NS_C14N_EXCL, "InclusiveNamespaces", PREFIX_C14N_EXCL);

    public static final String PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE = "PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE";
    public static final String PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION = "PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION";
    public static final String PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTED_KEY = "PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTED_KEY";

    public static final String PROP_APPEND_SIGNATURE_ON_THIS_ID = "PROP_APPEND_SIGNATURE_ON_THIS_ID";

    public static final Action SIGNATURE = new Action("SIGNATURE");
    public static final Action ENCRYPT = new Action("ENCRYPT");

    public static class Action implements Comparable<Action> {
        private final String name;

        protected Action(String name) {
            this.name = name;
        }

        public String toString() {
            return name;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof Action) {
                Action otherAction = (Action) obj;
                if (this.toString().equals(otherAction.toString())) {
                    return true;
                }
            }
            return false;
        }

        @Override
        public int hashCode() {
            return name != null ? name.hashCode() : 0;
        }

        @Override
        public int compareTo(Action o) {
            return this.toString().compareTo(o.toString());
        }
    }

    public static final KeyUsage Sym_Sig = new KeyUsage("Sym_Sig");
    public static final KeyUsage Asym_Sig = new KeyUsage("Asym_Sig");
    public static final KeyUsage Enc = new KeyUsage("Enc");

    public static class KeyUsage implements Comparable<KeyUsage> {
        private final String name;

        protected KeyUsage(String name) {
            this.name = name;
        }

        public String toString() {
            return name;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof KeyUsage) {
                KeyUsage otherKeyUsage = (KeyUsage) obj;
                if (this.toString().equals(otherKeyUsage.toString())) {
                    return true;
                }
            }
            return false;
        }

        @Override
        public int hashCode() {
            return name != null ? name.hashCode() : 0;
        }

        @Override
        public int compareTo(KeyUsage o) {
            return this.toString().compareTo(o.toString());
        }
    }

    public static class TokenType implements Comparable<TokenType> {
        private final String name;

        protected TokenType(String name) {
            this.name = name;
        }

        public String toString() {
            return name;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof TokenType) {
                TokenType otherTokenType = (TokenType) obj;
                if (this.toString().equals(otherTokenType.toString())) {
                    return true;
                }
            }
            return false;
        }

        @Override
        public int hashCode() {
            return name != null ? name.hashCode() : 0;
        }

        @Override
        public int compareTo(TokenType o) {
            return this.toString().compareTo(o.toString());
        }
    }

    public enum ContentType {
        PLAIN,
        SIGNATURE,
        ENCRYPTION
    }
}
