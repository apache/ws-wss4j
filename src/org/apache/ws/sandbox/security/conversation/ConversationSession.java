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
package org.apache.ws.security.conversation;

import org.apache.ws.security.conversation.message.info.DerivedKeyInfo;
import org.apache.ws.security.conversation.message.info.SecurityContextInfo;

import java.util.Hashtable;

/**
 * Class ConversationSession
 */
public class ConversationSession {

    /**
     * The security context info of this session
     */
    private SecurityContextInfo contextInfo;

    /**
     * The set of derived keys used in the session
     * Here a Hashtable is used to list the derived keys by their id's
     * This will be useful when selecting the relevant derived key in the key derivator
     */
    private Hashtable derivedKeys;

    /**
     * Creates a new conversation session for a gien security context
     * 
     * @param contextInfo The security context info
     */
    public ConversationSession(SecurityContextInfo contextInfo) {
        this.contextInfo = contextInfo;
        this.derivedKeys = new Hashtable();
    }

    /**
     * Returns the security context info of this session
     * 
     * @return the security context info of this session
     */
    public SecurityContextInfo getContextInfo() {
        return contextInfo;
    }

    /**
     * Returns the Hashtable of derived keys (<code>DerivedKeyInfo</code> obects) of
     * this session
     * 
     * @return A Hashtable of DerivedKeyInfo objects
     */
    public Hashtable getDerivedKeys() {
        return derivedKeys;
    }

    /**
     * This adds a derived key into the session
     * 
     * @param dkInfo The info object of the relevant derived key
     */
    public void addDerivedKey(DerivedKeyInfo dkInfo) {
        this.derivedKeys.put(dkInfo.getId(), dkInfo);
    }
}
