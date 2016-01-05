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

package org.apache.wss4j.common.bsp;

/**
 * A Basic Security Profile rule.
 */
@SuppressWarnings("checkstyle:linelength")
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
    R3227("A SECURITY_HEADER MUST NOT contain more than one TIMESTAMP"),

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