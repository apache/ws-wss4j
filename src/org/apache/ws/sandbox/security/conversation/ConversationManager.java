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

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.conversation.message.info.DerivedKeyInfo;
import org.apache.ws.security.conversation.message.token.DerivedKeyToken;
import org.w3c.dom.Document;

/**
 * This class helps handlers to carry on conversation. Actually the class is the
 * collection of set of methods that are common to both serside and client side
 * handlers.
 */
public class ConversationManager {

    /**
     * Adds Derived key tokens to the header of the SOAP message, given the
     * following parameters.
     * 
     * @param doc         
     * @param uuid        
     * @param dkcbHandler 
     * @param genID       
     * @throws WSSecurityException   
     * @throws ConversationException 
     */
    public void addDerivedKeyToken(Document doc, String uuid, DerivedKeyCallbackHandler dkcbHandler, String genID)
            throws WSSecurityException, ConversationException {
        // Derrive the token
        DerivedKeyToken dtoken = new DerivedKeyToken(doc);
        dtoken.setLabel(doc, "WSSecureConversationWSSecureConversation");
        genID = ConversationUtil.genericID();
        dtoken.setNonce(doc, "nonce.....");
        dtoken.setID(genID);

        // add the derived key token into the dkcbHandler
        String identifier = ConversationUtil.generateIdentifier(uuid,
                genID);
        DerivedKeyInfo dkInfo = new DerivedKeyInfo(dtoken);
        dkcbHandler.addDerivedKey(identifier, dkInfo);

        // add the token to the soap message
        DerivedKeyTokenAdder adder = new DerivedKeyTokenAdder();
        adder.build(doc, dtoken);
    }
}
