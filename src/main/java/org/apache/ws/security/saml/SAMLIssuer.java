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

package org.apache.ws.security.saml;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.saml.ext.AssertionWrapper;

/**
 * Builds a WS SAML Assertion and inserts it into the SOAP Envelope.
 * Refer to the WS specification, SAML Token profile
 *
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public interface SAMLIssuer {

    /**
     * Creates a new <code>AssertionWrapper</code>.
     * <p/>
     * A complete <code>AssertionWrapper</code> is constructed.
     *
     * @return AssertionWrapper
     * @throws WSSecurityException
     */
    public AssertionWrapper newAssertion() throws WSSecurityException;

    /**
     * @return Returns the issuerCrypto.
     */
    public Crypto getIssuerCrypto();

    /**
     * @return Returns the issuerKeyName.
     */
    public String getIssuerKeyName();

    /**
     * @return Returns the issuerKeyPassword.
     */
    public String getIssuerKeyPassword();

}
