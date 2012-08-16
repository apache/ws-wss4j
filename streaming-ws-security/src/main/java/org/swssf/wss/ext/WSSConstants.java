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
package org.swssf.wss.ext;

import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.impl.util.ConcreteLSInput;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.namespace.QName;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import java.util.*;

/**
 * WSSConstants for global use
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class WSSConstants extends XMLSecurityConstants {

    static {
        try {
            setJaxbContext(JAXBContext.newInstance("org.apache.ws.security.binding.wss10:org.apache.ws.security.binding.wss11:org.apache.ws.security.binding.wsu10:org.apache.ws.security.binding.wssc13:org.apache.ws.security.binding.wssc200502:org.apache.xml.security.binding.xmlenc:org.apache.xml.security.binding.xmldsig:org.apache.xml.security.binding.xmldsig11:org.apache.xml.security.binding.excc14n"));
            SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            schemaFactory.setResourceResolver(new LSResourceResolver() {
                @Override
                public LSInput resolveResource(String type, String namespaceURI, String publicId, String systemId, String baseURI) {
                    if ("http://www.w3.org/2001/XMLSchema.dtd".equals(systemId)) {
                        ConcreteLSInput concreteLSInput = new ConcreteLSInput();
                        concreteLSInput.setByteStream(XMLSecurityConstants.class.getClassLoader().getResourceAsStream("bindings/schemas/XMLSchema.dtd"));
                        return concreteLSInput;
                    } else if ("XMLSchema.dtd".equals(systemId)) {
                        ConcreteLSInput concreteLSInput = new ConcreteLSInput();
                        concreteLSInput.setByteStream(XMLSecurityConstants.class.getClassLoader().getResourceAsStream("bindings/schemas/XMLSchema.dtd"));
                        return concreteLSInput;
                    } else if ("datatypes.dtd".equals(systemId)) {
                        ConcreteLSInput concreteLSInput = new ConcreteLSInput();
                        concreteLSInput.setByteStream(XMLSecurityConstants.class.getClassLoader().getResourceAsStream("bindings/schemas/datatypes.dtd"));
                        return concreteLSInput;
                    } else if ("http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd".equals(systemId)) {
                        ConcreteLSInput concreteLSInput = new ConcreteLSInput();
                        concreteLSInput.setByteStream(XMLSecurityConstants.class.getClassLoader().getResourceAsStream("bindings/schemas/xmldsig-core-schema.xsd"));
                        return concreteLSInput;
                    } else if ("http://www.w3.org/2001/xml.xsd".equals(systemId)) {
                        ConcreteLSInput concreteLSInput = new ConcreteLSInput();
                        concreteLSInput.setByteStream(XMLSecurityConstants.class.getClassLoader().getResourceAsStream("bindings/schemas/xml.xsd"));
                        return concreteLSInput;
                    }
                    return null;
                }
            });
            Schema schema = schemaFactory.newSchema(
                    new Source[]{
                            new StreamSource(XMLSecurityConstants.class.getClassLoader().getResourceAsStream("schemas/soap-1.1.xsd")),
                            new StreamSource(XMLSecurityConstants.class.getClassLoader().getResourceAsStream("schemas/soap-1.2.xsd")),
                            new StreamSource(XMLSecurityConstants.class.getClassLoader().getResourceAsStream("bindings/schemas/exc-c14n.xsd")),
                            new StreamSource(XMLSecurityConstants.class.getClassLoader().getResourceAsStream("bindings/schemas/xmldsig-core-schema.xsd")),
                            new StreamSource(XMLSecurityConstants.class.getClassLoader().getResourceAsStream("bindings/schemas/xenc-schema.xsd")),
                            new StreamSource(XMLSecurityConstants.class.getClassLoader().getResourceAsStream("bindings/schemas/xmldsig11-schema.xsd")),
                            new StreamSource(XMLSecurityConstants.class.getClassLoader().getResourceAsStream("schemas/oasis-200401-wss-wssecurity-utility-1.0.xsd")),
                            new StreamSource(XMLSecurityConstants.class.getClassLoader().getResourceAsStream("schemas/oasis-200401-wss-wssecurity-secext-1.0.xsd")),
                            new StreamSource(XMLSecurityConstants.class.getClassLoader().getResourceAsStream("schemas/oasis-wss-wssecurity-secext-1.1.xsd")),
                            new StreamSource(XMLSecurityConstants.class.getClassLoader().getResourceAsStream("schemas/ws-secureconversation-200502.xsd")),
                            new StreamSource(XMLSecurityConstants.class.getClassLoader().getResourceAsStream("schemas/ws-secureconversation-1.3.xsd")),
                    }
            );
            setJaxbSchemas(schema);
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        } catch (SAXException e) {
            throw new RuntimeException(e);
        }
    }

    protected WSSConstants() {
    }

    public static final String TRANSPORT_SECURITY_ACTIVE = "transportSecurityActive";

    public static final String TIMESTAMP_PROCESSED = "TimestampProcessed";

    public static final String NS_WSSE10 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    public static final String NS_WSSE11 = "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd";
    public static final String NS_WSU10 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    public static final String NS_SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/";
    public static final String NS_SOAP12 = "http://www.w3.org/2003/05/soap-envelope";

    public static final String NS_WST = "http://schemas.xmlsoap.org/ws/2005/02/trust";
    public static final String NS_WSC_SCT = "http://schemas.xmlsoap.org/ws/2005/02/sc/sct";

    public static final String NS_SAML = "urn:oasis:names:tc:SAML:1.0:assertion";
    public static final String NS_SAML2 = "urn:oasis:names:tc:SAML:2.0:assertion";

    public static final String PREFIX_SOAPENV = "env";
    public static final String TAG_soap_Envelope_LocalName = "Envelope";
    public static final String TAG_soap_Header_LocalName = "Header";
    public static final String TAG_soap_Body_LocalName = "Body";

    public static final QName TAG_soap11_Envelope = new QName(NS_SOAP11, TAG_soap_Envelope_LocalName, PREFIX_SOAPENV);
    public static final QName TAG_soap11_Header = new QName(NS_SOAP11, TAG_soap_Header_LocalName, PREFIX_SOAPENV);
    public static final QName TAG_soap11_Body = new QName(NS_SOAP11, TAG_soap_Body_LocalName, PREFIX_SOAPENV);
    public static final QName ATT_soap11_Actor = new QName(NS_SOAP11, "actor", PREFIX_SOAPENV);

    public static final QName TAG_soap12_Envelope = new QName(NS_SOAP12, TAG_soap_Envelope_LocalName, PREFIX_SOAPENV);
    public static final QName TAG_soap12_Header = new QName(NS_SOAP12, TAG_soap_Header_LocalName, PREFIX_SOAPENV);
    public static final QName TAG_soap12_Body = new QName(NS_SOAP12, TAG_soap_Body_LocalName, PREFIX_SOAPENV);
    public static final QName ATT_soap12_Role = new QName(NS_SOAP12, "role", PREFIX_SOAPENV);

    public static final String PREFIX_WSSE = "wsse";
    public static final String PREFIX_WSSE11 = "wsse11";
    public static final QName TAG_wsse_Security = new QName(NS_WSSE10, "Security", PREFIX_WSSE);

    public static final QName TAG_wsse_SecurityTokenReference = new QName(NS_WSSE10, "SecurityTokenReference", PREFIX_WSSE);
    public static final QName TAG_wsse_Reference = new QName(NS_WSSE10, "Reference", PREFIX_WSSE);
    public static final QName ATT_wsse_Usage = new QName(NS_WSSE10, "Usage", PREFIX_WSSE);
    public static final QName ATT_wsse11_TokenType = new QName(NS_WSSE11, "TokenType", PREFIX_WSSE11);

    public static final QName TAG_wsse_KeyIdentifier = new QName(NS_WSSE10, "KeyIdentifier", PREFIX_WSSE);
    public static final QName ATT_NULL_EncodingType = new QName(null, "EncodingType");
    public static final QName ATT_NULL_ValueType = new QName(null, "ValueType");

    public static final QName TAG_wsse_BinarySecurityToken = new QName(NS_WSSE10, "BinarySecurityToken", PREFIX_WSSE);
    public static final String PREFIX_WSU = "wsu";
    public static final QName ATT_wsu_Id = new QName(NS_WSU10, "Id", PREFIX_WSU);

    public static final QName TAG_wsse11_EncryptedHeader = new QName(NS_WSSE11, "EncryptedHeader", PREFIX_WSSE11);

    public static final QName TAG_wsse_TransformationParameters = new QName(NS_WSSE10, "TransformationParameters", PREFIX_WSSE);

    public static final QName TAG_wsu_Timestamp = new QName(NS_WSU10, "Timestamp", PREFIX_WSU);
    public static final QName TAG_wsu_Created = new QName(NS_WSU10, "Created", PREFIX_WSU);
    public static final QName TAG_wsu_Expires = new QName(NS_WSU10, "Expires", PREFIX_WSU);

    public static final String NS10_SOAPMESSAGE_SECURITY = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0";
    public static final String NS11_SOAPMESSAGE_SECURITY = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1";

    public static final String NS_X509TOKEN_PROFILE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0";

    public static final String NS_X509_V3_TYPE = NS_X509TOKEN_PROFILE + "#X509v3";
    public static final String NS_X509PKIPathv1 = NS_X509TOKEN_PROFILE + "#X509PKIPathv1";
    public static final String NS_X509SubjectKeyIdentifier = NS_X509TOKEN_PROFILE + "#X509SubjectKeyIdentifier";
    public static final String NS_THUMBPRINT = NS11_SOAPMESSAGE_SECURITY + "#ThumbprintSHA1";

    public static final String SOAPMESSAGE_NS10_BASE64_ENCODING = NS10_SOAPMESSAGE_SECURITY + "#Base64Binary";

    public static final QName TAG_wsse_UsernameToken = new QName(NS_WSSE10, "UsernameToken", PREFIX_WSSE);
    public static final QName TAG_wsse_Username = new QName(NS_WSSE10, "Username", PREFIX_WSSE);
    public static final QName TAG_wsse_Password = new QName(NS_WSSE10, "Password", PREFIX_WSSE);
    public static final QName TAG_wsse_Nonce = new QName(NS_WSSE10, "Nonce", PREFIX_WSSE);
    public static final QName TAG_wsse11_Salt = new QName(NS_WSSE11, "Salt", PREFIX_WSSE11);
    public static final QName TAG_wsse11_Iteration = new QName(NS_WSSE11, "Iteration", PREFIX_WSSE11);

    public static final String NS_USERNAMETOKEN_PROFILE11 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0";
    public static final String NS_PASSWORD_DIGEST = NS_USERNAMETOKEN_PROFILE11 + "#PasswordDigest";
    public static final String NS_PASSWORD_TEXT = NS_USERNAMETOKEN_PROFILE11 + "#PasswordText";
    public static final String NS_USERNAMETOKEN_PROFILE_UsernameToken = NS_USERNAMETOKEN_PROFILE11 + "#UsernameToken";

    public static final QName TAG_wsse11_SignatureConfirmation = new QName(NS_WSSE11, "SignatureConfirmation", PREFIX_WSSE11);
    public static final QName ATT_NULL_Value = new QName(null, "Value");

    public static final String NS_C14N_EXCL = "http://www.w3.org/2001/10/xml-exc-c14n#";
    public static final String PREFIX_C14N_EXCL = "c14nEx";

    public static final QName TAG_wst_BinarySecret = new QName(NS_WST, "BinarySecret");

    public static final String SOAPMESSAGE_NS10_STRTransform = NS10_SOAPMESSAGE_SECURITY + "#STR-Transform";
    public static final String SWA_ATTACHMENT_CONTENT_SIG_TRANS = "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform";
    public static final String SWA_ATTACHMENT_COMPLETE_SIG_TRANS = "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Complete-Signature-Transform";

    public static final QName TAG_saml_Assertion = new QName(NS_SAML, "Assertion");
    public static final QName TAG_saml2_Assertion = new QName(NS_SAML2, "Assertion");

    public static final String NS_SAML10_TOKEN_PROFILE = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0";
    public static final String NS_SAML11_TOKEN_PROFILE = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1";
    public static final String NS_SAML10_TYPE = NS_SAML10_TOKEN_PROFILE + "#SAMLAssertionID";
    public static final String NS_SAML20_TYPE = NS_SAML11_TOKEN_PROFILE + "#SAMLID";
    public static final String NS_SAML11_TOKEN_PROFILE_TYPE = NS_SAML11_TOKEN_PROFILE + "#SAMLV1.1";
    public static final String NS_SAML20_TOKEN_PROFILE_TYPE = NS_SAML11_TOKEN_PROFILE + "#SAMLV2.0";

    public static final QName ATT_NULL_AssertionID = new QName(null, "AssertionID");
    public static final QName ATT_NULL_ID = new QName(null, "ID");


    public static final String NS_WSC_05_02 = "http://schemas.xmlsoap.org/ws/2005/02/sc";
    public static final String NS_WSC_05_12 = "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512";
    public static final String PREFIX_WSC = "wsc";

    public static final QName TAG_wsc0502_SecurityContextToken = new QName(NS_WSC_05_02, "SecurityContextToken", PREFIX_WSC);
    public static final QName TAG_wsc0512_SecurityContextToken = new QName(NS_WSC_05_12, "SecurityContextToken", PREFIX_WSC);
    public static final QName TAG_wsc0502_Identifier = new QName(NS_WSC_05_02, "Identifier", PREFIX_WSC);
    public static final QName TAG_wsc0512_Identifier = new QName(NS_WSC_05_12, "Identifier", PREFIX_WSC);

    public static final QName TAG_wsc0502_DerivedKeyToken = new QName(NS_WSC_05_02, "DerivedKeyToken", PREFIX_WSC);
    public static final QName TAG_wsc0512_DerivedKeyToken = new QName(NS_WSC_05_12, "DerivedKeyToken", PREFIX_WSC);
    public static final QName TAG_wsc0502_Properties = new QName(NS_WSC_05_02, "Properties", PREFIX_WSC);
    public static final QName TAG_wsc0512_Properties = new QName(NS_WSC_05_02, "Properties", PREFIX_WSC);
    public static final QName TAG_wsc0502_Length = new QName(NS_WSC_05_02, "Length", PREFIX_WSC);
    public static final QName TAG_wsc0512_Length = new QName(NS_WSC_05_02, "Length", PREFIX_WSC);
    public static final QName TAG_wsc0502_Generation = new QName(NS_WSC_05_02, "Generation", PREFIX_WSC);
    public static final QName TAG_wsc0512_Generation = new QName(NS_WSC_05_02, "Generation", PREFIX_WSC);
    public static final QName TAG_wsc0502_Offset = new QName(NS_WSC_05_02, "Offset", PREFIX_WSC);
    public static final QName TAG_wsc0512_Offset = new QName(NS_WSC_05_02, "Offset", PREFIX_WSC);
    public static final QName TAG_wsc0502_Label = new QName(NS_WSC_05_02, "Label", PREFIX_WSC);
    public static final QName TAG_wsc0512_Label = new QName(NS_WSC_05_02, "Label", PREFIX_WSC);
    public static final QName TAG_wsc0502_Nonce = new QName(NS_WSC_05_02, "Nonce", PREFIX_WSC);
    public static final QName TAG_wsc0512_Nonce = new QName(NS_WSC_05_02, "Nonce", PREFIX_WSC);

    public static final String P_SHA_1 = "http://schemas.xmlsoap.org/ws/2005/02/sc/dk/p_sha1";
    public static final String P_SHA_1_2005_12 = "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1";
    public static final String WS_SecureConversation_DEFAULT_LABEL = "WS-SecureConversation";

    public static final String NS_WSS_ENC_KEY_VALUE_TYPE = NS11_SOAPMESSAGE_SECURITY + "#EncryptedKey";

    public static final String PROP_USE_THIS_TOKEN_ID_FOR_DERIVED_KEY = "PROP_USE_THIS_TOKEN_ID_FOR_DERIVED_KEY";
    public static final String PROP_USE_THIS_TOKEN_ID_FOR_SECURITYCONTEXTTOKEN = "PROP_USE_THIS_TOKEN_ID_FOR_SECURITYCONTEXTTOKEN";

    public static final String PROP_TIMESTAMP_SECURITYEVENT = "PROP_TIMESTAMP";

    /**
     * Length of UsernameToken derived key used by .NET WSE to sign a message.
     */
    public static final int WSE_DERIVED_KEY_LEN = 16;
    public static final String LABEL_FOR_DERIVED_KEY = "WS-Security";

    public static final Action SIGNATURE = new Action(XMLSecurityConstants.SIGNATURE.toString());
    public static final Action ENCRYPT = new Action(XMLSecurityConstants.ENCRYPT.toString());
    public static final Action TIMESTAMP = new Action("TIMESTAMP");
    public static final Action USERNAMETOKEN = new Action("USERNAMETOKEN");
    public static final Action USERNAMETOKEN_SIGNED = new Action("USERNAMETOKEN_SIGNED");
    public static final Action SIGNATURE_CONFIRMATION = new Action("SIGNATURE_CONFIRMATION");
    public static final Action SIGNATURE_WITH_DERIVED_KEY = new Action("SIGNATURE_WITH_DERIVED_KEY");
    public static final Action ENCRYPT_WITH_DERIVED_KEY = new Action("ENCRYPT_WITH_DERIVED_KEY");
    public static final Action SAML_TOKEN_SIGNED = new Action("SAML_TOKEN_SIGNED");
    public static final Action SAML_TOKEN_UNSIGNED = new Action("SAML_TOKEN_UNSIGNED");

    public static class Action extends XMLSecurityConstants.Action {
        protected Action(String name) {
            super(name);
        }
    }

    //todo rename KeyUsage because C14N, etc are not keys...
    public static final KeyUsage Comp_Key = new KeyUsage("Comp_Key");
    public static final KeyUsage Enc_KD = new KeyUsage("Enc_KD");
    public static final KeyUsage Sig_KD = new KeyUsage("Sig_KD");
    public static final KeyUsage Soap_Norm = new KeyUsage("Soap_Norm");
    public static final KeyUsage STR_Trans = new KeyUsage("STR_Trans");
    public static final KeyUsage XPath = new KeyUsage("XPath");

    public static final TokenType UsernameToken = new TokenType("UsernameToken");
    public static final TokenType SecurityContextToken = new TokenType("SecurityContextToken");
    public static final TokenType Saml10Token = new TokenType("Saml10Token");
    public static final TokenType Saml11Token = new TokenType("Saml11Token");
    public static final TokenType Saml20Token = new TokenType("Saml20Token");
    public static final TokenType IssuedToken = new TokenType("IssuedToken");
    public static final TokenType SecureConversationToken = new TokenType("SecureConversationToken");
    public static final TokenType HttpsToken = new TokenType("HttpsToken");
    public static final TokenType KerberosToken = new TokenType("KerberosToken");
    public static final TokenType SpnegoContextToken = new TokenType("SpnegoContextToken");
    public static final TokenType RelToken = new TokenType("RelToken");
    public static final TokenType DerivedKeyToken = new TokenType("DerivedKeyToken");

    public enum WSSKeyIdentifierType implements KeyIdentifierType {
        ISSUER_SERIAL,
        SECURITY_TOKEN_DIRECT_REFERENCE,
        X509_KEY_IDENTIFIER,
        SKI_KEY_IDENTIFIER,
        THUMBPRINT_IDENTIFIER,
        EMBEDDED_KEYIDENTIFIER_REF,
        USERNAMETOKEN_REFERENCE,
        KEY_VALUE,
        SECURITY_TOKEN_REFERENCE,
    }

    public enum DerivedKeyTokenReference {
        DirectReference,
        EncryptedKey,
        SecurityContextToken,
    }

    public enum UsernameTokenPasswordType {
        PASSWORD_NONE(null),
        PASSWORD_TEXT(NS_PASSWORD_TEXT),
        PASSWORD_DIGEST(NS_PASSWORD_DIGEST);

        private final String namespace;
        private static final Map<String, UsernameTokenPasswordType> lookup = new HashMap<String, UsernameTokenPasswordType>();

        static {
            for (UsernameTokenPasswordType u : EnumSet.allOf(UsernameTokenPasswordType.class))
                lookup.put(u.getNamespace(), u);
        }

        UsernameTokenPasswordType(String namespace) {
            this.namespace = namespace;
        }

        public String getNamespace() {
            return namespace;
        }

        public static UsernameTokenPasswordType getUsernameTokenPasswordType(String namespace) {
            return lookup.get(namespace);
        }
    }

    public static final List<QName> SOAP_11_BODY_PATH = new ArrayList<QName>(2);
    public static final List<QName> SOAP_11_HEADER_PATH = new ArrayList<QName>(2);
    public static final List<QName> WSSE_SECURITY_HEADER_PATH = new ArrayList<QName>(3);

    static {
        SOAP_11_BODY_PATH.add(WSSConstants.TAG_soap11_Envelope);
        SOAP_11_BODY_PATH.add(WSSConstants.TAG_soap11_Body);

        SOAP_11_HEADER_PATH.add(WSSConstants.TAG_soap11_Envelope);
        SOAP_11_HEADER_PATH.add(WSSConstants.TAG_soap11_Header);

        WSSE_SECURITY_HEADER_PATH.addAll(SOAP_11_HEADER_PATH);
        WSSE_SECURITY_HEADER_PATH.add(WSSConstants.TAG_wsse_Security);

    }

    public enum BSPRule {
        R3203("A TIMESTAMP MUST contain exactly one CREATED"),
        R3224("Any TIMESTAMP MUST NOT contain more than one EXPIRES"),
        R3221("Any TIMESTAMP containing an EXPIRES MUST contain a CREATED that precedes its sibling EXPIRES"),
        R3222("Any TIMESTAMP MUST NOT contain anything other than CREATED or EXPIRES elements"),
        R3220("Any CREATED SHOULD NOT contain a seconds value with more than three digits to the right of the decimal (milliseconds)"),
        R3229("Any EXPIRES SHOULD NOT contain a seconds value with more than three digits to the right of the decimal (milliseconds)"),
        R3213("Any CREATED containing second values MUST specify seconds values less than 60"),
        R3215("Any EXPIRES containing second values MUST specify seconds values less than 60"),
        R3225("Any CREATED MUST NOT include a ValueType attribute"),
        R3226("Any EXPIRES MUST NOT include a ValueType attribute"),
        R3217("Any CREATED MUST contain time values in UTC format as specified by the XML Schema type (dateTime)"),
        R3223("Any EXPIRES MUST contain time values in UTC format as specified by the XML Schema type (dateTime)"),

        R3061("A SECURITY_TOKEN_REFERENCE MUST provide exactly one token reference"),
        R3074("Any wsse:11:TokenType Attribute in a SECURITY_TOKEN_REFERENCE MUST specify a value that a TokenType specified by a security token profile for the referenced SECURITY_TOKEN"),
        R3057("Any STR_REFERENCE MUST NOT reference a SECURITY_TOKEN_REFERENCE"),
        R3064("Any STR_REFERENCE MUST NOT reference an STR_EMBEDDED"),
        R3059("Any STR_REFERENCE MUST specify a ValueType attribute with the exception of STR_REFERENCE pointing to a SAML_V2_0_TOKEN or a KERBEROS_TOKEN or an ENCRYPTED_KEY_TOKEN"),
        R3058("Any STR_REFERENCE ValueType attribute MUST contain a value for the referenced SECURITY_TOKEN specified by the corresponding security token profile"),
        R3062("Any STR_REFERENCE MUST specify a URI attribute"),
        R3027("Any SECURITY_TOKEN_REFERENCE MUST NOT contain an STR_KEY_NAME"),
        R3054("Any STR_KEY_IDENTIFIER MUST specify a ValueType attribute"),
        R3063("Any STR_KEY_IDENTIFIER ValueType attribute MUST contain a value specified within the security token profile associated with the referenced SECURITY_TOKEN"),
        R3070("Any STR_KEY_IDENTIFIER that refers to a SECURITY_TOKEN other than a SAML_TOKEN MUST specify an EncodingType attribute"),
        R3071("Any STR_KEY_IDENTIFIER EncodingType attribute MUST have a value of \"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\""),
        R3060("Any STR_EMBEDDED MUST contain only a single child element which is an INTERNAL_SECURITY_TOKEN"),
        R3025("Any INTERNAL_SECURITY_TOKEN contained in an STR_EMBEDDED MUST be in the same format as if it were a child of a SECURITY_HEADER"),
        R3056("Any STR_EMBEDDED MUST NOT contain a wsse:SecurityTokenReference child element"),
        R3022("Any SECURITY_TOKEN_REFERENCE that references an INTERNAL_SECURITY_TOKEN which has a wsu:Id attribute MUST contain an STR_REFERENCE or STR_EMBEDDED"),
        R3023("Any SECURITY_TOKEN_REFERENCE that references an INTERNAL_SECURITY_TOKEN that is referenced several times SHOULD contain an STR_REFERENCE rather than an STR_EMBEDDED"),
        R5204("Any STR_REFERENCE to an INTERNAL_SECURITY_TOKEN having an ID attribute MUST contain a URI attribute with a Shorthand XPointer value"),
        R5205("Any INTERNAL_SECURITY_TOKEN that is not contained in an STR_EMBEDDED MUST precede all SECURITY_TOKEN_REFERENCE elements that reference it in the SOAP_ENVELOPE"),
        R3066("Any STR_REFERENCE that is a descendant of a SECURITY_HEADER MUST NOT use a Shorthand XPointer to refer to an INTERNAL_SECURITY_TOKEN located in a SECURITY_HEADER other than the SECURITY_HEADER that contains the STR_REFERENCE"),
        R3067("Any STR_REFERENCE that is a descendant of an ENCRYPTED_DATA MUST NOT use a Shorthand XPointer to refer to an INTERNAL_SECURITY_TOKEN located in a SECURITY_HEADER other than the SECURITY_HEADER containing a reference (EK_REFERENCE_LIST or an ENC_REFERENCE_LIST) to the ENCRYPTED_DATA"),
        R3024("Any EXTERNAL_TOKEN_REFERENCE that can use an STR_REFERENCE MUST contain an STR_REFERENCE"),
        R3211("Any SECURITY_TOKEN_REFERENCE MUST NOT reference a ds:KeyInfo element"),

        R3102("A SIGNATURE MUST NOT be an Enveloping Signature as defined by the XML Signature specification"),
        R3104("A SIGNATURE SHOULD NOT be an Enveloped Signature as defined by the XML Signature specification"),
        R3103("A SIGNATURE SHOULD be a Detached Signature as defined by the XML Signature specification"),
        R3001("Any SIG_REFERENCE SHOULD contain a URI attribute containing a Shorthand XPointer"),
        R3003("Any SIG_REFERENCE to a SIGNATURE or descendant of a SIGNATURE MUST contain a URI attribute with a reference value that is a Shorthand XPointer to Local ID attribute defined by XML Signature"),
        R3004("Any SIG_REFERENCE to an element defined in XML Encryption MUST contain a URI attribute with a reference value that is a Shorthand XPointer to Local ID attribute defined by XML Encryption"),
        R3005("Any SIG_REFERENCE to an element that is not defined in XML Encryption, a SIGNATURE, or a descendant of a SIGNATURE SHOULD contain a URI attribute with a reference value that is a Shorthand XPointer to a wsu:Id attribute"),
        R3002("Any SIG_REFERENCE to an element that does not have an ID attribute MUST contain a TRANSFORM with an Algorithm attribute value of \"http://www.w3.org/2002/06/xmldsig-filter2\""),
        R5416("Any SIG_REFERENCE MUST contain a SIG_TRANSFORMS child element"),
        R5411("Any SIG_TRANSFORMS MUST contain at least one SIG_TRANSFORM child element"),
        R5423("Any SIG_TRANSFORM Algorithm attribute MUST have a value of \"http://www.w3.org/2001/10/xml-exc-c14n#\" or \"http://www.w3.org/2002/06/xmldsig-filter2\" or \"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform\" or \"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" or \"http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform\" or \"http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Complete-Signature-Transform\""),
        R5412("Any SIG_TRANSFORMS MUST contain as its last child a SIG_TRANSFORM with an Algorithm attribute with a value of \"http://www.w3.org/2001/10/xml-exc-c14n#\" or \"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform\" or \"http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform\" or \"http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Complete-Signature-Transform\""),
        R5407("Any SIG_TRANSFORM with an Algorithm attribute with a value of \"http://www.w3.org/2001/10/xml-exc-c14n#\" MUST contain an INCLUSIVE_NAMESPACES with an PrefixList attribute unless the PrefixList is empty"),
        R5413("Any SIG_TRANSFORM with an Algorithm attribute with a value of \"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform\" MUST have an INCLUSIVE_NAMESPACES with an PrefixList attribute unless the PrefixList is empty"),
        R3065("Any SIG_TRANSFORM with an Algorithm attribute with a value of \"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform\" MUST contain a child wsse:TransformationParameters element containing a child ds:CanonicalizationMethod element"),
        R5404("Any CANONICALIZATION_METHOD Algorithm attribute MUST have a value of \"http://www.w3.org/2001/10/xml-exc-c14n#\" indicating that it uses Exclusive C14N without comments for canonicalization"),
        R5406("Any CANONICALIZATION_METHOD MUST contain an INCLUSIVE_NAMESPACES with a PrefixList attribute unless the PrefixList is empty"),
        R5414("A RECEIVER MUST be capable of accepting and processing an INCLUSIVE_NAMESPACES PrefixList attribute containing prefixes in any order within the string"),
        R5415("A RECEIVER MUST be capable of accepting and processing an INCLUSIVE_NAMESPACES PrefixList attribute containing arbitrary whitespace before, after and between the prefixes within the string"),
        R5405("Any INCLUSIVE_NAMESPACES MUST contain the prefix of all namespaces that are in-scope and desired to be protected, but not visibly utilized, for the element being signed and its descendants, per Exclusive XML Canonicalization Version 1.0"),
        R5408("Any INCLUSIVE_NAMESPACES MUST contain the string \"#default\" if a default namespace is in-scope and desired to be protected, but not visibly utilized, for the element being signed and its descendants, per Exclusive XML Canonicalization Version 1.0"),
        R5420("Any DIGEST_METHOD Algorithm attribute SHOULD have the value \"http://www.w3.org/2000/09/xmldsig#sha1\""),
        R5421("Any SIGNATURE_METHOD Algorithm attribute SHOULD have a value of \"http://www.w3.org/2000/09/xmldsig#hmac-sha1\" or \"http://www.w3.org/2000/09/xmldsig#rsa-sha1\""),
        R5401("Any SIGNATURE_METHOD MUST NOT contain a ds:HMACOutputLength child element"),
        R5402("Any SIG_KEY_INFO MUST contain exactly one child element"),
        R5417("Any SIG_KEY_INFO MUST contain a SECURITY_TOKEN_REFERENCE child element"),
        R5403("A SIGNATURE MUST NOT contain a ds:Manifest descendant element"),
        R5440("A SIGNATURE MUST NOT have any xenc:EncryptedData elements amongst its descendants"),
        R5441("A SIGNATURE_CONFIRMATION MUST contain a wsu:Id attribute"),

        R3228("A soap:Header element in a SECURE_ENVELOPE MUST NOT contain any child ENCRYPTED_DATA"),
        R3299("A soap:Header element in a SECURE_ENVELOPE MAY contain ENCRYPTED_HEADER children"),
        R3230("An ENCRYPTED_HEADER MUST NOT contain any children other than a single required ENCRYPTED_DATA"),
        R3232("In cases where a wsu:Id does exist on the ENCRYPTED_HEADER, the child ENCRYPTED_DATA MAY contain an Id attribute"),
        R3205("Any ENC_REFERENCE_LIST produced as part of an encryption step MUST use a single key"),
        R3231("Any ENC_REFERENCE_LIST MUST contain an xenc:DataReference element for each ENCRYPTED_DATA produced in the associated encryption step"),
        R3214("Any EK_REFERENCE_LIST MUST contain a xenc:DataReference for each ENCRYPTED_DATA produced in the associated encryption step"),
        R3208("Any ENCRYPTED_KEY MUST precede any ENCRYPTED_DATA in the same SECURITY_HEADER referenced by the associated EK_REFERENCE_LIST"),
        R3209("Any ENCRYPTED_KEY MUST NOT specify a Type attribute"),
        R5622("Any ENCRYPTED_KEY MUST NOT specify a MimeType attribute"),
        R5623("Any ENCRYPTED_KEY MUST NOT specify a Encoding attribute"),
        R5602("Any ENCRYPTED_KEY MUST NOT contain a Recipient attribute"),
        R5603("Any ENCRYPTED_KEY MUST contain an xenc:EncryptionMethod child element"),
        R5629("An ENCRYPTED_DATA which is not referenced from an ENCRYPTED_KEY MUST contain a ds:KeyInfo"),
        R5624("In cases where a wsu:Id does not exist on the ENCRYPTED_HEADER, the child ENCRYPTED_DATA MUST contain an ID attribute"),
        R5627("In cases where an ID does not exist on the ENCRYPTED_DATA, the parent ENCRYPTED_HEADER MUST contain a wsu:Id attribute"),
        R5601("Any ENCRYPTED_DATA MUST contain an xenc:EncryptionMethod child element"),
        R5424("Any ENC_KEY_INFO MUST have exactly one child element"),
        R5426("Any ENC_KEY_INFO MUST contain a child SECURITY_TOKEN_REFERENCE"),
        R5608("Any ENC_DATA_REFERENCE MUST contain a URI attribute containing a Shorthand XPointer reference value based on either the Id attribute of the referenced ENCRYPTED_DATA or the wsu:Id attribute of the referenced ENCRYPTED_HEADER"),
        R3006("Any EK_DATA_REFERENCE MUST contain a URI attribute containing a Shorthand XPointer reference value based on either the Id attribute of the referenced ENCRYPTED_DATA or the wsu:Id attribute of the referenced ENCRYPTED_HEADER"),
        R5613("Any ENC_KEY_REFERENCE MUST contain a URI attribute containing a Shorthand XPointer reference value based on the Id attribute of the referred to ENCRYPTED_KEY"),
        R3007("Any EK_KEY_REFERENCE MUST contain a URI attribute containing a Shorthand XPointer reference value based on the Id attribute of the referred to ENCRYPTED_KEY"),
        R5620("Any ED_ENCRYPTION_METHOD Algorithm attribute MUST have a value of \"http://www.w3.org/2001/04/xmlenc#tripledes-cbc\", \"http://www.w3.org/2001/04/xmlenc#aes128-cbc\" or \"http://www.w3.org/2001/04/xmlenc#aes256-cbc\""),
        R5621("When used for Key Transport, any EK_ENCRYPTION_METHOD Algorithm attribute MUST have a value of \"http://www.w3.org/2001/04/xmlenc#rsa-1_5\" or \"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\""),
        R5625("When used for Key Wrap, any EK_ENCRYPTION_METHOD Algorithm attribute MUST have a value of \"http://www.w3.org/2001/04/xmlenc#kw-tripledes\", \"http://www.w3.org/2001/04/xmlenc#kw-aes128\", or \"http://www.w3.org/2001/04/xmlenc#kw-aes256\""),
        R5626("Any EK_ENCRYPTION_METHOD Algorithm attribute MUST have a value of \"http://www.w3.org/2001/04/xmlenc#rsa-1_5\" or \"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\" or \"http://www.w3.org/2001/04/xmlenc#kw-tripledes\" or \"http://www.w3.org/2001/04/xmlenc#kw-aes128\" or \"http://www.w3.org/2001/04/xmlenc#kw-aes256\""),
        R5614("A HEADER encrypted as a result of an encryption step MUST be replaced by a corresponding ENCRYPTED_HEADER"),
        R5606("Any encrypted element or element content within a SECURE_ENVELOPE, encrypted as a result of an encryption step, MUST be replaced by a corresponding ENCRYPTED_DATA, unless the element is a HEADER_ELEMENT"),

        R3029("Any BINARY_SECURITY_TOKEN MUST specify an EncodingType attribute"),
        R3030("Any BINARY_SECURITY_TOKEN EncodingType attribute MUST have a value of \"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\""),
        R3031("Any BINARY_SECURITY_TOKEN MUST specify an ValueType attribute"),
        R3032("Any BINARY_SECURITY_TOKEN ValueType attribute MUST have a value specified by the related security token profile"),

        R4222("Any USERNAME_TOKEN MUST NOT have more than one PASSWORD"),
        R4201("Any PASSWORD MUST specify a Type attribute"),
        R4212("Any PASSWORD with a Type attribute value of \"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\" MUST have its value computed using the following formula, where \"+\" indicates concatenation: Password_Digest = Base64 ( SHA-1 ( nonce + created + password ) ). That is, concatenate the text forms of the nonce, creation time, and the password (or shared secret or password equivalent), digest the combination using the SHA-1 hash algorithm, then include the Base64 encoding of that result as the password (digest). Any elements that are not present are simply omitted from the concatenation"),
        R4216("When a SECURITY_TOKEN_REFERENCE, within a SIGNATURE or ENCRYPTED_KEY, refers to a SECURITY_TOKEN named wsse:UsernameToken to derive a key, the key MUST be derived using the algorithm specified in Section 4 of Web Services Security: UsernameToken Profile 1.1"),
        R4217("When a SECURITY_TOKEN_REFERENCE, within a SIGNATURE or ENCRYPTED_KEY, refers to a SECURITY_TOKEN named wsse:UsernameToken to derive a key, the SECURITY_TOKEN MUST contain a wsse11:Salt child element"),
        R4218("When a SECURITY_TOKEN_REFERENCE, within a SIGNATURE or ENCRYPTED_KEY, refers to a SECURITY_TOKEN named wsse:UsernameToken to derive a key, the SECURITY_TOKEN MUST contain a wsse11:Iteration child element with a value greater than or equal to 1000"),
        R4223("Any USERNAME_TOKEN MUST NOT have more than one CREATED"),
        R4225("Any USERNAME_TOKEN MUST NOT have more than one NONCE"),
        R4220("Any NONCE MUST specify an EncodingType attribute"),
        R4221("Any NONCE EncodingType attribute MUST have a value of \"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\""),
        R4214("Any STR_REFERENCE to a USERNAME_TOKEN MUST have a ValueType attribute with a value of \"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#UsernameToken\""),
        R4215("Any SECURITY_TOKEN_REFERENCE to a USERNAME_TOKEN MUST NOT contain an STR_KEY_IDENTIFIER"),

        R3033("Any X509_TOKEN MUST contain a ValueType attribute with a value of \"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\""),
        R5201("Any BINARY_SECURITY_TOKEN containing an X.509 Certificate Path MUST be either a PKCS7_TOKEN or a PKIPATH_TOKEN"),
        R5202("Any BINARY_SECURITY_TOKEN containing an X.509 Certificate Path SHOULD be a PKIPATH_TOKEN"),
        R5211("Any PKCS7_TOKEN MUST contain a ValueType attribute with a value of \"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#PKCS7\""),
        R5218("Any STR_REFERENCE to a X509_TOKEN MUST contain a ValueType attribute with a value of \"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\""),
        R5212("Any SECURITY_TOKEN_REFERENCE to a PKCS7_TOKEN MUST contain a wsse11:TokenType attribute with a value of \"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#PKCS7\""),
        R5213("Any STR_REFERENCE to a PKCS7_TOKEN MUST contain a ValueType attribute with a value of \"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#PKCS7\""),
        R5214("Any PKIPATH_TOKEN MUST contain a ValueType attribute with a value of \"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509PKIPathv1\""),
        R5215("Any SECURITY_TOKEN_REFERENCE to a PKIPATH_TOKEN MUST contain a wsse11:TokenType attribute with a value of \"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509PKIPathv1\""),
        R5216("Any STR_REFERENCE to a PKIPATH_TOKEN MUST contain a ValueType attribute with a value of \"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509PKIPathv1\""),
        R5209("When a SECURITY_TOKEN_REFERENCE references an EXTERNAL_SECURITY_TOKEN that cannot be referred to using an STR_REFERENCE but can be referred to using an STR_KEY_IDENTIFIER or STR_ISSUER_SERIAL, an STR_KEY_IDENTIFIER or STR_ISSUER_SERIAL MUST be used"),
        R5206("Any STR_KEY_IDENTIFIER that references an X509_TOKEN MUST have a ValueType attribute with the value of \"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier\" or \"http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1\""),
        R5208("Any STR_KEY_IDENTIFIER that references an X509_TOKEN and has a ValueType attribute with the value of \"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier\" MUST contain the value of the token's SubjectKeyIdentifier extension"),
        R5210("Any STR_KEY_IDENTIFIER that references an X509_TOKEN which does not contain a SubjectKeyIdentifier extension MUST have a ValueType attribute with the value of \"http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1\" and MUST contain the value of the SHA1 of the raw octets of the X509_TOKEN that is referenced"),
        R5409("Any STR_ISSUER_SERIAL MUST contain a value following the encoding rules specified in the XML Signature specification for DNames"),

        R6304("Any STR_REFERENCE to a REL_TOKEN MUST contain a ValueType attribute with a value of \"http://docs.oasis-open.org/wss/oasis-wss-rel-token-profile-1.0.pdf#license\""),
        R6301("Any STR_REFERENCE to a INTERNAL_SECURITY_TOKEN that is an REL_TOKEN containing a wsu:Id attribute, MUST NOT use a licenseId reference"),
        R6302("Any SECURITY_HEADER child elements MUST be ordered so that any SIGNATURE necessary to verify the issuance of an REL_TOKEN precedes the first SECURITY_TOKEN_REFERENCE that refers to that REL_TOKEN"),

        R6902("Any KERBEROS_TOKEN MUST contain a ValueType attribute with a value of \"http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ\""),
        R6903("Any KERBEROS_TOKEN MUST be an INTERNAL_SECURITY_TOKEN in the initial SECURE_ENVELOPE of an authenticated message exchange between a SENDER and RECEIVER"),
        R6904("Any KERBEROS_TOKEN MUST be an EXTERNAL_SECURITY_TOKEN in each SECURE_ENVELOPE after the initial SECURE_ENVELOPE of an authenticated message exchange between a SENDER and RECEIVER"),
        R6907("Any SECURITY_TOKEN_REFERENCE to a KERBEROS_TOKEN MUST contain a wsse11:TokenType attribute with a value of \"http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ\""),
        R6906("Any STR_KEY_IDENTIFIER to a KERBEROS_TOKEN MUST contain a ValueType attribute with a value of \"http://docs.oasis-open.org/wss/oasis-wss-kerberos-tokenprofile-1.1#Kerberosv5APREQSHA1\""),
        R6905("Any SECURITY_TOKEN_REFERENCE to an EXTERNAL_SECURITY_TOKEN which is a KERBEROS_TOKEN MUST contain an STR_KEY_IDENTIFIER"),

        R6601("Any SAML_SC_KEY_INFO MUST NOT contain a reference to a SAML_TOKEN"),
        R6611("Any SECURITY_TOKEN_REFERENCE to a SAML_V1_1_TOKEN MUST contain a wsse11:TokenType attribute with a value of \"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1\""),
        R6617("Any SECURITY_TOKEN_REFERENCE to a SAML_V2_0_TOKEN MUST contain a wsse11:TokenType attribute with a value of \"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0\""),
        R6614("Any SECURITY_TOKEN_REFERENCE that references an INTERNAL_SAML_V2_0_TOKEN using a STR_REFERENCE MUST NOT contain a ValueType attribute"),
        R6602("Any STR_KEY_IDENTIFIER that references a INTERNAL_SAML_TOKEN MUST include a ValueType attribute"),
        R6609("Any STR_KEY_IDENTIFIER that references a EXTERNAL_SAML_TOKEN MUST include a ValueType attribute"),
        R6603("Any STR_KEY_IDENTIFIER ValueType attribute that references a SAML_V1_1_TOKEN MUST have a value of \"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID\""),
        R6616("Any STR_KEY_IDENTIFIER ValueType attribute that references a SAML_V2_0_TOKEN MUST have a value of \"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID\""),
        R6604("Any STR_KEY_IDENTIFIER that references a SAML_TOKEN MUST NOT include an EncodingType attribute"),
        R6605("Any STR_KEY_IDENTIFIER that references a SAML_TOKEN MUST have a value encoded as an xs:string"),
        R6610("Any SECURITY_TOKEN_REFERENCE that references an INTERNAL_SAML_TOKEN that has an ID attribute, the reference MUST contain an STR_REFERENCE or an STR_EMBEDDED"),
        R6612("Any SIG_REFERENCE to a SECURITY_TOKEN_REFERENCE which contains an STR_EMBEDDED which contains an INTERNAL_SAML_V2_0_TOKEN MUST NOT include a SIG_TRANSFORM with an Algorithm attribute value of \"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform\""),
        R6606("Any SECURITY_TOKEN_REFERENCE that references an EXTERNAL_SAML_TOKEN MUST contain a SAML_AUTHORITY_BINDING"),
        R6607("Any AuthorityKind attribute of a SAML_AUTHORITY_BINDING MUST have a value of saml:AssertionIDReference"),
        R6608("Any SECURITY_TOKEN_REFERENCE that references an INTERNAL_SAML_TOKEN MUST NOT contain a SAML_AUTHORITY_BINDING"),
        R6613("Any SECURITY_TOKEN_REFERENCE to an EXTERNAL_SAML_V2_0_TOKEN MUST contain an STR_REFERENCE"),

        R3069("Any SECURITY_TOKEN_REFERENCE to a ENCRYPTED_KEY_TOKEN MUST contain a wsse11:TokenType attribute with a value of \"http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey\""),
        R3072("Any STR_KEY_IDENTIFIER element in a SECURITY_TOKEN_REFERENCE that refers to an ENCRYPTED_KEY_TOKEN MUST contain a ValueType attribute with a value of \"http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKeySHA1\"");

        private final String msg;

        private BSPRule(String msg) {
            this.msg = msg;
        }

        public String getMsg() {
            return msg;
        }
    }


    /****************************************************************************
     * Fault codes defined in the WSS 1.1 spec under section 12, Error handling
     */

    /**
     * An unsupported token was provided
     */
    public static final QName UNSUPPORTED_SECURITY_TOKEN = new QName(NS_WSSE10, "UnsupportedSecurityToken");

    /**
     * An unsupported signature or encryption algorithm was used
     */
    public static final QName UNSUPPORTED_ALGORITHM = new QName(NS_WSSE10, "UnsupportedAlgorithm");

    /**
     * An error was discovered processing the <Security> header
     */
    public static final QName INVALID_SECURITY = new QName(NS_WSSE10, "InvalidSecurity");

    /**
     * An invalid security token was provided
     */
    public static final QName INVALID_SECURITY_TOKEN = new QName(NS_WSSE10, "InvalidSecurityToken");

    /**
     * The security token could not be authenticated or authorized
     */
    public static final QName FAILED_AUTHENTICATION = new QName(NS_WSSE10, "FailedAuthentication");

    /**
     * The signature or decryption was invalid
     */
    public static final QName FAILED_CHECK = new QName(NS_WSSE10, "FailedCheck");

    /**
     * Referenced security token could not be retrieved
     */
    public static final QName SECURITY_TOKEN_UNAVAILABLE = new QName(NS_WSSE10, "SecurityTokenUnavailable");

    /**
     * The message has expired
     */
    public static final QName MESSAGE_EXPIRED = new QName(NS_WSSE10, "MessageExpired");
}
