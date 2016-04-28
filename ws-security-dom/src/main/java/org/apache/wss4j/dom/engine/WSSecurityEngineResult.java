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

package org.apache.wss4j.dom.engine;

import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.token.BinarySecurity;
import org.apache.wss4j.dom.WSDataRef;
import org.apache.wss4j.dom.message.token.SecurityContextToken;
import org.apache.wss4j.dom.message.token.SignatureConfirmation;
import org.apache.wss4j.dom.message.token.Timestamp;
import org.apache.wss4j.dom.message.token.UsernameToken;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.List;

@SuppressWarnings("deprecation")
public class WSSecurityEngineResult extends org.apache.wss4j.dom.WSSecurityEngineResult {
    
    /**
     * 
     */
    private static final long serialVersionUID = -245449156013140037L;

    public WSSecurityEngineResult(int act) {
        super(act);
    }

    public WSSecurityEngineResult(
        int act,
        SamlAssertionWrapper ass
    ) {
        super(act, ass);
    }

    public WSSecurityEngineResult(
        int act,
        Principal princ,
        X509Certificate[] certs,
        byte[] sv
    ) {
        super(act, princ, certs, sv);
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
        super(act, decryptedKey, encryptedKeyBytes, dataRefUris);
    }

    public WSSecurityEngineResult(
        int act,
        byte[] decryptedKey,
        byte[] encryptedKeyBytes,
        List<WSDataRef> dataRefUris,
        X509Certificate[] certs
    ) {
        super(act, decryptedKey, encryptedKeyBytes, dataRefUris, certs);
    }

    public WSSecurityEngineResult(int act, List<WSDataRef> dataRefUris) {
        super(act, dataRefUris);
    }

    public WSSecurityEngineResult(int act, Timestamp tstamp) {
        super(act, tstamp);
    }

    public WSSecurityEngineResult(int act, SecurityContextToken sct) {
        super(act, sct);
    }

    public WSSecurityEngineResult(int act, SignatureConfirmation sc) {
        super(act, sc);
    }

    public WSSecurityEngineResult(int act, UsernameToken usernameToken) {
        super(act, usernameToken);
    }

    public WSSecurityEngineResult(int act, UsernameToken usernameToken, Principal principal) {
        super(act, usernameToken, principal);
    }

    public WSSecurityEngineResult(int act, BinarySecurity token, X509Certificate[] certs) {
        super(act, token, certs);
    }

}
