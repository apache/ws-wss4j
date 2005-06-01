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
package org.apache.ws.security.conversation.message.info;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.conversation.message.token.SecurityContextToken;
import org.apache.ws.security.trust.message.token.RequestedProofToken;

/**
 * @author Kau
 * @author Ruchith
 */
public class SecurityContextInfo {

    private Log log = LogFactory.getLog(SecurityContextInfo.class.getName());

    /**
     * Shared secret taken from the RequestedProofToken
     */
    private byte[] sharedSecret;

    /**
     * Identifier of the SecurityContextToken
     */
    private String identifier;

    /**
     * The frequency at which the keys are derived
     * If this frequency is set to 0 then keys are not derived and the shared secret
     * is used to sign/encrypt messages
     */
    private int frequency;

    /**
     * This element will be useful to store in the hashtable to get
     * information about the security context
     *
     * @param securityContextToken
     * @param requestedProofToken
     */
    public SecurityContextInfo(SecurityContextToken securityContextToken,
                               RequestedProofToken requestedProofToken,
                               int frequency) throws WSSecurityException {
        this.sharedSecret = requestedProofToken.getSharedSecret();
        this.identifier = securityContextToken.getIdentifier();
        this.frequency = frequency; // frequency of refreshing the derrived key
        log.debug("SecurityContextInfo: created. SCT Identifier: " + identifier);
        /** @todo get the values of other elements (any elements) of SCT*/
    }

    /**
     * TEMPORARY METHOD FOR TESTING ONLY TIL I GET THE LATEST PROOF TOKEN
     * This element will be useful to store in the hashtable to get
     * information about the security context
     *
     * @param securityContextToken
     * @param requestedProofToken
     */
    public SecurityContextInfo(SecurityContextToken securityContextToken,
                               byte[] sharedSecret,
                               int frequency) throws WSSecurityException {

        this.sharedSecret = sharedSecret;
        this.identifier = securityContextToken.getIdentifier();
        this.frequency = frequency; // frequency of refreshing the derrived key
        /** @todo get the values of other elements (any elements) of SCT*/
    }
    
    
	public SecurityContextInfo(String uuid,
								   byte[] sharedSecret,
								   int frequency) throws WSSecurityException {

			this.sharedSecret = sharedSecret;
			this.identifier = uuid;
			this.frequency = frequency; // frequency of refreshing the derrived key
			/** @todo get the values of other elements (any elements) of SCT*/
	}
     
    /**
     * @return
     */
    public int getFrequency() {
        return frequency;
    }

    /**
     * @return
     */
    public String getIdentifier() {
        return identifier;
    }

    /**
     * @return
     */
    public byte[] getSharedSecret() {
        return sharedSecret;
    }

}
