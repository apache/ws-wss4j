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

package org.apache.wss4j.common.saml.builder;


/**
 * Class SAML2Constants provides static constant definitions associated with
 * the SAML v2.x specification.
 */
public final class SAML2Constants {
    //
    // NAME ID FORMAT
    //

    public static final String NAMEID_FORMAT_UNSPECIFIED =
        "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

    public static final String NAMEID_FORMAT_EMAIL_ADDRESS =
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

    public static final String NAMEID_FORMAT_X509_SUBJECT_NAME =
        "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";

    public static final String NAMEID_FORMAT_WINDOWS_DQN =
        "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName";

    public static final String NAMEID_FORMAT_KERBEROS =
        "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos";

    public static final String NAMEID_FORMAT_ENTITY =
        "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";

    public static final String NAMEID_FORMAT_PERSISTENT =
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

    public static final String NAMEID_FORMAT_TRANSIENT =
        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";

    //
    // SUBJECT CONFIRMATION
    //

    public static final String CONF_BEARER =
        "urn:oasis:names:tc:SAML:2.0:cm:bearer";

    public static final String CONF_HOLDER_KEY =
        "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";

    public static final String CONF_SENDER_VOUCHES =
        "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches";

    //
    // AUTH CONTEXT CLASS REF
    //

    public static final String AUTH_CONTEXT_CLASS_REF_INTERNET_PROTOCOL =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol";

    public static final String AUTH_CONTEXT_CLASS_REF_INTERNET_PROTOCOL_PASSWORD =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword";

    public static final String AUTH_CONTEXT_CLASS_REF_KERBEROS =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos";

    public static final String AUTH_CONTEXT_CLASS_REF_MOBILE_ONE_FACTOR_UNREGISTERED =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorUnregistered";

    public static final String AUTH_CONTEXT_CLASS_REF_MOBILE_TWO_FACTOR_UNREGISTERED =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered";

    public static final String AUTH_CONTEXT_CLASS_REF_MOBILE_ONE_FACTOR_CONTRACT =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorContract";

    public static final String AUTH_CONTEXT_CLASS_REF_MOBILE_TWO_FACTOR_CONTRACT =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract";

    public static final String AUTH_CONTEXT_CLASS_REF_PASSWORD =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";

    public static final String AUTH_CONTEXT_CLASS_REF_PASSWORD_PROTECTED_TRANSPORT =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

    public static final String AUTH_CONTEXT_CLASS_REF_PREVIOUS_SESSION =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession";

    public static final String AUTH_CONTEXT_CLASS_REF_X509 =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:X509";

    public static final String AUTH_CONTEXT_CLASS_REF_PGP =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PGP";

    public static final String AUTH_CONTEXT_CLASS_REF_SPKI =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:SPKI";

    public static final String AUTH_CONTEXT_CLASS_REF_XMLDSIG =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:XMLDSig";

    public static final String AUTH_CONTEXT_CLASS_REF_SMARTCARD =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard";

    public static final String AUTH_CONTEXT_CLASS_REF_SMARTCARD_PKI =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI";

    public static final String AUTH_CONTEXT_CLASS_REF_SOFTWARE_PKI =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI";

    public static final String AUTH_CONTEXT_CLASS_REF_TELEPHONY =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:Telephony";

    public static final String AUTH_CONTEXT_CLASS_REF_NOMAD_TELEPHONY =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:NomadTelephony";

    public static final String AUTH_CONTEXT_CLASS_REF_PERSONAL_TELEPHONY =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PersonalTelephony";

    public static final String AUTH_CONTEXT_CLASS_REF_AUTHENTICATED_TELEPHONY =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:AuthenticatedTelephony";

    public static final String AUTH_CONTEXT_CLASS_REF_SECURED_REMOTE_PASSWORD =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:SecureRemotePassword";

    public static final String AUTH_CONTEXT_CLASS_REF_TLS_CLIENT =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient";

    public static final String AUTH_CONTEXT_CLASS_REF_TIME_SYNC_TOKEN =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken";

    public static final String AUTH_CONTEXT_CLASS_REF_UNSPECIFIED =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";

    //
    // ATTRIBUTE NAME FORMAT
    //

    public static final String ATTRNAME_FORMAT_UNSPECIFIED =
        "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";

    public static final String ATTRNAME_FORMAT_URI =
        "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";

    public static final String ATTRNAME_FORMAT_BASIC =
        "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";

    private SAML2Constants() {
        // Complete
    }
}
