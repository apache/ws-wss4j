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

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.conversation.message.token.DerivedKeyToken;
import org.apache.ws.security.message.token.SecurityTokenReference;

import java.util.Hashtable;

/**
 * Class DerivedKeyInfo
 */
public class DerivedKeyInfo {

    /**
     * Field properties
     */
    private Hashtable properties;

    /**
     * Field id
     */
    private String id;

    /**
     * Field generation
     */
    private int generation;

    /**
     * Field offset
     */
    private int offset;

    /**
     * Field length
     */
    private long length;

    /**
     * Field label
     */
    private String label;

    /**
     * Field nonce
     */
    private String nonce;

    /**
     * Field usageCount
     */
    private int usageCount;

    /**
     * Field secTokenRef
     */
    private SecurityTokenReference secTokenRef;

    /**
     * Constructor DerivedKeyInfo
     * 
     * @param dkt 
     * @throws WSSecurityException 
     */
    public DerivedKeyInfo(DerivedKeyToken dkt) throws WSSecurityException {
        this.properties = dkt.getProperties();
        this.generation = dkt.getGeneration();
        this.offset = dkt.getOffset();
        this.length = dkt.getLength();
        this.label = dkt.getLabel();
        this.nonce = dkt.getNonce();
        this.id = dkt.getID();

        // I need this info in the KeyDerivator
        // Please feel free to suggest a better method to get the reference info into the KeyDerivator
        this.secTokenRef = dkt.getSecuityTokenReference();
    }

    /**
     * Method getGeneration
     * 
     * @return 
     */
    public int getGeneration() {
        return generation;
    }

    /**
     * Method getLabel
     * 
     * @return 
     */
    public String getLabel() {
        return label;
    }

    /**
     * Method getLength
     * 
     * @return 
     */
    public long getLength() {
        return length;
    }

    /**
     * Method getNonce
     * 
     * @return 
     */
    public String getNonce() {
        return nonce;
    }

    /**
     * Method getOffset
     * 
     * @return 
     */
    public int getOffset() {
        return offset;
    }

    /**
     * Method getProperties
     * 
     * @return 
     */
    public Hashtable getProperties() {
        return properties;
    }

    /**
     * Method getId
     * 
     * @return 
     */
    public String getId() {
        return id;
    }

    /**
     * Method getSecurityTokenReference
     * 
     * @return 
     */
    public SecurityTokenReference getSecurityTokenReference() {
        return secTokenRef;
    }
}
