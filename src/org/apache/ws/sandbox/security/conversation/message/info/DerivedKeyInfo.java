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
import org.apache.ws.security.conversation.message.token.DerivedKeyToken;
import org.apache.ws.security.message.token.SecurityTokenReference;

import java.util.Hashtable;

/**
 * @author Ruchith
 * @version 1.0
 */

public class DerivedKeyInfo {

    private Log log = LogFactory.getLog(DerivedKeyInfo.class.getName());

    private Hashtable properties;
    private String id;
    private String algorithm;
    private int generation;
    private int offset;
    private long length;
    private String label;
    private String nonce;
    private int usageCount;
    private SecurityTokenReference secTokenRef;
    private SecurityTokenReference secTokRef2DkToken;

    public DerivedKeyInfo(DerivedKeyToken dkt) throws WSSecurityException {
        this.properties = dkt.getProperties();
        this.generation = dkt.getGeneration();
        this.offset = dkt.getOffset();
        this.length = dkt.getLength();
        this.label = dkt.getLabel();
        this.nonce = dkt.getNonce();
        this.id = dkt.getID();
        this.algorithm = dkt.getAlgorithm();
        //I need this info in the KeyDerivator
        //Please feel free to suggest a better method to get the reference info into the KeyDerivator
        this.secTokenRef = dkt.getSecuityTokenReference();
        log.debug("DerivedKeyInfo :created. dktId: " + this.id);
    }

    public int getGeneration() {
        return generation;
    }

    public String getLabel() {
        return label;
    }

    public long getLength() {
        return length;
    }

    public String getNonce() {
        return nonce;
    }

    public int getOffset() {
        return offset;
    }

    public Hashtable getProperties() {
        return properties;
    }

    public String getId() {
        return this.id;
    }

    public SecurityTokenReference getSecurityTokenReference() {
        return secTokenRef;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * @param reference
     */
    public void setSecTokRef2DkToken(SecurityTokenReference reference) {
        secTokRef2DkToken = reference;
    }

    public SecurityTokenReference getSecTokRef2DkToken() {
        return secTokRef2DkToken;
    }
}