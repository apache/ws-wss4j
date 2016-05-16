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
package org.apache.wss4j.stax.securityEvent;

import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;

public abstract class WSSecurityEventConstants extends SecurityEventConstants {

    public static final Event NO_SECURITY = new Event("NoSecurity");
    public static final Event OPERATION = new Event("Operation");
    public static final Event TIMESTAMP = new Event("Timestamp");
    public static final Event SIGNED_PART = new Event("SignedPart");
    public static final Event ENCRYPTED_PART = new Event("EncryptedPart");
    public static final Event REQUIRED_ELEMENT = new Event("RequiredElement");
    public static final Event REQUIRED_PART = new Event("RequiredPart");
    public static final Event ISSUED_TOKEN = new Event("IssuedToken");
    public static final Event KERBEROS_TOKEN = new Event("KerberosToken");
    public static final Event SAML_TOKEN = new Event("SamlToken");
    public static final Event SECURITY_CONTEXT_TOKEN = new Event("SecurityContextToken");
    public static final Event REL_TOKEN = new Event("RelToken");
    public static final Event USERNAME_TOKEN = new Event("UsernameToken");
    public static final Event HTTPS_TOKEN = new Event("HttpsToken");
    public static final Event DERIVED_KEY_TOKEN = new Event("DerivedKeyToken");
    public static final Event SIGNATURE_CONFIRMATION = new Event("SignatureConfirmation");
    
    // CHECKSTYLE:OFF
    @Deprecated public static final Event NoSecurity = new Event("NoSecurity");
    @Deprecated public static final Event Operation = new Event("Operation");
    @Deprecated public static final Event Timestamp = new Event("Timestamp");
    @Deprecated public static final Event SignedPart = new Event("SignedPart");
    @Deprecated public static final Event EncryptedPart = new Event("EncryptedPart");
    @Deprecated public static final Event RequiredElement = new Event("RequiredElement");
    @Deprecated public static final Event RequiredPart = new Event("RequiredPart");
    @Deprecated public static final Event IssuedToken = new Event("IssuedToken");
    @Deprecated public static final Event KerberosToken = new Event("KerberosToken");
    @Deprecated public static final Event SamlToken = new Event("SamlToken");
    @Deprecated public static final Event SecurityContextToken = new Event("SecurityContextToken");
    @Deprecated public static final Event RelToken = new Event("RelToken");
    @Deprecated public static final Event UsernameToken = new Event("UsernameToken");
    @Deprecated public static final Event HttpsToken = new Event("HttpsToken");
    @Deprecated public static final Event DerivedKeyToken = new Event("DerivedKeyToken");
    @Deprecated public static final Event SignatureConfirmation = new Event("SignatureConfirmation");
    // CHECKSTYLE:ON

}
