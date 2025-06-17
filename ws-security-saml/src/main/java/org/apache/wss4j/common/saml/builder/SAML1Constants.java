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
 * Class SAML1Constants provides static constant definitions associated with
 * the SAML v1.x specification.
 */
public final class SAML1Constants {

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

    //
    // SUBJECT CONFIRMATION
    //

    /**
     * Assertion Bearer Confirmation Method Identifier
     */
    public static final String CONF_BEARER =
        "urn:oasis:names:tc:SAML:1.0:cm:bearer";

    /**
     * Holder of Key Confirmation Method Identifier
     */
    public static final String CONF_HOLDER_KEY =
        "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key";

    /**
     * Sender Vouches Confirmation Method Identifier
     */
    public static final String CONF_SENDER_VOUCHES =
        "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches";

    //
    // AUTH METHOD
    //

    /**
     * The authentication was performed by means of a password.
     */
    public static final String AUTH_METHOD_PASSWORD =
        "urn:oasis:names:tc:SAML:1.0:am:password";

    /**
     * The authentication was performed by means of the Kerberos protocol [RFC 1510],
     * an instantiation of the Needham-Schroeder symmetric key authentication mechanism [Needham78].
     */
    public static final String AUTH_METHOD_KERBEROS = "urn:ietf:rfc:1510";

    /**
     * The authentication was performed by means of Secure Remote Password protocol as specified in
     * [RFC 2945].
     */
    public static final String AUTH_METHOD_SRP = "urn:ietf:rfc:2945";

    /**
     * The authentication was performed by means of an unspecified hardware token.
     */
    public static final String AUTH_METHOD_HARDWARE_TOKEN =
        "urn:oasis:names:tc:SAML:1.0:am:HardwareToken";

    /**
     * The authentication was performed using either the SSL or TLS protocol with certificate
     * based client authentication. TLS is described in [RFC 2246].
     */
    public static final String AUTH_METHOD_TLS_CLIENT = "urn:ietf:rfc:2246";

    /**
     * The authentication was performed by some (unspecified) mechanism on a key authenticated by
     * means of an X.509 PKI [X.500][PKIX]. It may have been one of the mechanisms for which a more
     * specific identifier has been defined.
     */
    public static final String AUTH_METHOD_X509 =
        "urn:oasis:names:tc:SAML:1.0:am:X509-PKI";

    /**
     * The authentication was performed by some (unspecified) mechanism on a key authenticated by
     * means of a PGP web of trust [PGP]. It may have been one of the mechanisms for which a more
     * specific identifier has been defined.
     */
    public static final String AUTH_METHOD_PGP =
        "urn:oasis:names:tc:SAML:1.0:am:PGP";

    /**
     * The authentication was performed by some (unspecified) mechanism on a key authenticated by
     * means of a SPKI PKI [SPKI]. It may have been one of the mechanisms for which a more specific
     * identifier has been defined.
     */
    public static final String AUTH_METHOD_SPKI =
        "urn:oasis:names:tc:SAML:1.0:am:SPKI";

    /**
     * The authentication was performed by some (unspecified) mechanism on a key authenticated by
     * means of a XKMS trust service [XKMS]. It may have been one of the mechanisms for which a more
     * specific identifier has been defined.
     */
    public static final String AUTH_METHOD_XKMS =
        "urn:oasis:names:tc:SAML:1.0:am:XKMS";

    /**
     * The authentication was performed by means of an XML digital signature [RFC 3075].
     */
    public static final String AUTH_METHOD_DSIG = "urn:ietf:rfc:3075";

    /**
     * The authentication was performed by an unspecified means.
     */
    public static final String AUTH_METHOD_UNSPECIFIED =
        "urn:oasis:names:tc:SAML:1.0:am:unspecified";

    private SAML1Constants() {
        // Complete
    }
}
