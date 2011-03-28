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

package org.apache.ws.security;

import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.SecurityContextToken;
import org.apache.ws.security.message.token.SignatureConfirmation;
import org.apache.ws.security.message.token.Timestamp;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.saml.ext.AssertionWrapper;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * @author Werner Dittmann (Werner.Dittmann@t-online.de)
 */
public class WSSecurityEngineResult extends java.util.HashMap<String, Object> {
    
    //
    // Tokens
    //
    
    /**
     * 
     */
    private static final long serialVersionUID = 458604104267263765L;

    /**
     * Tag denoting the SAML Assertion found, if applicable.
     *
     * The value under this tag is of type AssertionWrapper.
     */
    public static final String TAG_SAML_ASSERTION = "saml-assertion";
    
    /**
     * Tag denoting the timestamp found, if applicable.
     *
     * The value under this tag is of type
     * org.apache.ws.security.message.token.Timestamp.
     */
    public static final String TAG_TIMESTAMP = "timestamp";

    /**
     * Tag denoting references to the DOM elements that have been
     * cryptographically protected.
     *
     * The value under this tag is of type SecurityContextToken.
     */
    public static final String TAG_SECURITY_CONTEXT_TOKEN = "security-context-token";
    
    /**
     * Tag denoting a UsernameToken object
     */
    public static final String TAG_USERNAME_TOKEN = "username-token";
    
    /**
     * Tag denoting a DerivedKeyToken object
     */
    public static final String TAG_DERIVED_KEY_TOKEN = "derived-key-token";
    
    /**
     * Tag denoting the signature confirmation of a signed element,
     * if applicable.
     *
     * The value under this tag is of type
     * org.apache.ws.security.message.token.SignatureConfirmation.
     */
    public static final java.lang.String TAG_SIGNATURE_CONFIRMATION = "signature-confirmation";

    /**
     * Tag denoting the X.509 certificate found, if applicable.
     *
     * The value under this tag is of type java.security.cert.X509Certificate.
     */
    public static final String TAG_BINARY_SECURITY_TOKEN = "binary-security-token";
    
    /**
     * Tag denoting a Transformed Token. For certain tokens, the Validator may return
     * an AssertionWrapper instance which corresponds to a transformed version of the
     * initial token. For example, a Username Token credential might be validated
     * by an STS and transformed into a SAML Assertion. This tag then holds the 
     * transformed AssertionWrapper instance, as a component of the Result corresponding
     * to the Username Token.
     * 
     * The value under this tag is of type AssertionWrapper.
     */
    public static final String TAG_TRANSFORMED_TOKEN = "transformed-token";
    
    //
    // Keys and certs
    //
    
    /**
     * Tag denoting the X.509 certificate found, if applicable.
     *
     * The value under this tag is of type java.security.cert.X509Certificate.
     */
    public static final String TAG_X509_CERTIFICATE = "x509-certificate";

    /**
     * Tag denoting the signature value of a signed element, if applicable.
     *
     * The value under this tag is of type byte[].
     */
    public static final String TAG_SIGNATURE_VALUE = "signature-value";
    
    /**
     * Tag denoting the X.509 certificate chain found, if applicable.
     *
     * The value under this tag is of type java.security.cert.X509Certificate[].
     */
    public static final String TAG_X509_CERTIFICATES = "x509-certificates";

    /**
     * Tag denoting the encrypted key bytes
     *
     * The value under this tag is a byte array 
     */
    public static final String TAG_ENCRYPTED_EPHEMERAL_KEY = "encrypted-ephemeral-key-bytes";
    
    /**
     * Tag denoting a byte[] secret associated with this token
     */
    public static final String TAG_SECRET = "secret";
    
    //
    // General tags
    //

    /**
     * Tag denoting the cryptographic operation performed
     *
     * The value under this tag is of type java.lang.Integer
     */
    public static final String TAG_ACTION = "action";

    /**
     * Tag denoting the security principal found, if applicable.
     *
     * The value under this tag is of type java.security.Principal.
     */
    public static final String TAG_PRINCIPAL = "principal";

    /**
     * Tag denoting references to a List of Data ref URIs.
     *
     * The value under this tag is of type List.
     */
    public static final String TAG_DATA_REF_URIS = "data-ref-uris";

    /**
     * Tag denoting the encrypted key transport algorithm.
     *
     * The value under this tag is of type String.
     */
    public static final String TAG_ENCRYPTED_KEY_TRANSPORT_METHOD = "encrypted-key-transport-method";
    
    /**
     * Tag denoting the algorithm that was used to sign the message
     *
     * The value under this tag is of type String.
     */
    public static final String TAG_SIGNATURE_METHOD = "signature-method";

    /**
     * Tag denoting the algorithm that was used to do canonicalization
     *
     * The value under this tag is of type String.
     */
    public static final String TAG_CANONICALIZATION_METHOD = "canonicalization-method";
    
    /**
     * The (wsu) Id of the token corresponding to this result.
     */
    public static final String TAG_ID = "id";
    
    public WSSecurityEngineResult(
        int act, 
        AssertionWrapper ass
    ) {
        put(TAG_ACTION, new Integer(act));
        put(TAG_SAML_ASSERTION, ass);
    }

    public WSSecurityEngineResult(
        int act, 
        Principal princ,
        X509Certificate[] certs, 
        byte[] sv
    ) {
        put(TAG_ACTION, new Integer(act));
        put(TAG_PRINCIPAL, princ);
        put(TAG_X509_CERTIFICATES, certs);
        put(TAG_SIGNATURE_VALUE, sv);
        if (certs != null) {
            put(TAG_X509_CERTIFICATE, certs[0]);
        }
    }

    public
    WSSecurityEngineResult(
        int act,
        Principal princ,
        X509Certificate[] certs,
        List<WSDataRef> dataRefs,
        byte[] sv
    ) {
        this(act, princ, certs, sv);
        put(TAG_DATA_REF_URIS, dataRefs);
    }
    
    public WSSecurityEngineResult(
        int act, 
        byte[] decryptedKey, 
        byte[] encryptedKeyBytes,
        List<WSDataRef> dataRefUris
    ) {
        put(TAG_ACTION, new Integer(act));
        put(TAG_SECRET, decryptedKey);
        put(TAG_ENCRYPTED_EPHEMERAL_KEY, encryptedKeyBytes);
        put(TAG_DATA_REF_URIS, dataRefUris);
    }
    
    public WSSecurityEngineResult(
        int act, 
        byte[] decryptedKey, 
        byte[] encryptedKeyBytes,
        List<WSDataRef> dataRefUris,
        X509Certificate[] certs
    ) {
        put(TAG_ACTION, new Integer(act));
        put(TAG_SECRET, decryptedKey);
        put(TAG_ENCRYPTED_EPHEMERAL_KEY, encryptedKeyBytes);
        put(TAG_DATA_REF_URIS, dataRefUris);
        put(TAG_X509_CERTIFICATES, certs);
        if (certs != null) {
            put(TAG_X509_CERTIFICATE, certs[0]);
        }
    }
    
    public WSSecurityEngineResult(int act, List<WSDataRef> dataRefUris) {
        put(TAG_ACTION, new Integer(act));
        put(TAG_DATA_REF_URIS, dataRefUris);
    }
    
    public WSSecurityEngineResult(int act, Timestamp tstamp) {
        put(TAG_ACTION, new Integer(act));
        put(TAG_TIMESTAMP, tstamp);
    }
    
    public WSSecurityEngineResult(int act, SecurityContextToken sct) {
        put(TAG_ACTION, new Integer(act));
        put(TAG_SECURITY_CONTEXT_TOKEN, sct);
    }
    
    public WSSecurityEngineResult(int act, SignatureConfirmation sc) {
        put(TAG_ACTION, new Integer(act));
        put(TAG_SIGNATURE_CONFIRMATION, sc);
    }
    
    public WSSecurityEngineResult(int act, UsernameToken usernameToken, Principal principal) {
        put(TAG_ACTION, new Integer(act));
        put(TAG_USERNAME_TOKEN, usernameToken);
        put(TAG_PRINCIPAL, principal);
    }

    public WSSecurityEngineResult(int act, BinarySecurity token, X509Certificate[] certs) {
        put(TAG_ACTION, new Integer(act));
        put(TAG_BINARY_SECURITY_TOKEN, token);
        put(TAG_X509_CERTIFICATES, certs);
        if (certs != null) {
            put(TAG_X509_CERTIFICATE, certs[0]);
        }
    }

    
}
