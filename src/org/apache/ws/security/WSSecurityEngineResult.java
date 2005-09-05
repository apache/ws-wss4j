/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.apache.ws.security;

import org.apache.ws.security.message.token.Timestamp;
import org.opensaml.SAMLAssertion;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Vector;

/**
 * @author Werner Dittmann (Werner.Dittmann@siemens.com)
 */
public class WSSecurityEngineResult {

    private int action;
    private Principal principal;
    private X509Certificate cert;
    private SAMLAssertion assertion;
    private Timestamp timestamp;
    private Vector signedElementQnames;
    private byte[] signatureValue = null;

    WSSecurityEngineResult(int act, SAMLAssertion ass) {
        principal = null;
        cert = null;
        action = act;
        assertion = ass;
    }

    WSSecurityEngineResult(int act, Principal princ,
            X509Certificate certificate, Vector elemQnames, byte[] sv) {
        principal = princ;
        action = act;
        cert = certificate;
        signedElementQnames = elemQnames;
        signatureValue = sv;
    }

    WSSecurityEngineResult(int act,
                           Timestamp tstamp) {
        action = act;
        timestamp = tstamp;
    }

    /**
     * @return the actions vector. These actions were performed by the the
     *         security engine.
     */
    public int getAction() {
        return action;
    }

    /**
     * @return the principals found if UsernameToken or Signature
     *         processing were done
     */
    public Principal getPrincipal() {
        return principal;
    }

    /**
     * @return the Certificate found if Signature
     *         processing were done
     */
    public X509Certificate getCertificate() {
        return cert;
    }

    /**
     * @return Returns the assertion.
     */
    public SAMLAssertion getAssertion() {
        return assertion;
    }

    /**
     * @return the timestamp found
     */
    public Timestamp getTimestamp() {
        return timestamp;
    }

    /**
     * @return Returns the signedElementQnames.
     */
    public Vector getSignedElementQnames() {
        return signedElementQnames;
    }

    /**
     * @return Returns the signatureValue.
     */
    public byte[] getSignatureValue() {
        return signatureValue;
    }
    
}
