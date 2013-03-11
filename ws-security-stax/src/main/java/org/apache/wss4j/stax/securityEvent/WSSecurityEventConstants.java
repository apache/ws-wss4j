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
    
    public static final Event Operation = new Event("Operation");
    public static final Event Timestamp = new Event("Timestamp");
    public static final Event SignedPart = new Event("SignedPart");
    public static final Event EncryptedPart = new Event("EncryptedPart");
    public static final Event RequiredElement = new Event("RequiredElement");
    public static final Event RequiredPart = new Event("RequiredPart");
    public static final Event IssuedToken = new Event("IssuedToken");
    public static final Event KerberosToken = new Event("KerberosToken");
    public static final Event SpnegoContextToken = new Event("SpnegoContextToken");
    public static final Event SamlToken = new Event("SamlToken");
    public static final Event SecurityContextToken = new Event("SecurityContextToken");
    public static final Event SecureConversationToken = new Event("SecureConversationToken");
    public static final Event RelToken = new Event("RelToken");
    public static final Event UsernameToken = new Event("UsernameToken");
    public static final Event HttpsToken = new Event("HttpsToken");
    public static final Event DerivedKeyToken = new Event("DerivedKeyToken");
    
}
