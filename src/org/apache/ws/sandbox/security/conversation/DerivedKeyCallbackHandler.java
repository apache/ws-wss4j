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

import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.conversation.message.info.DerivedKeyInfo;
import org.apache.ws.security.conversation.message.info.SecurityContextInfo;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.util.Hashtable;

/**
 * Class DerivedKeyCallbackHandler
 */
public class DerivedKeyCallbackHandler implements CallbackHandler {

    /**
     * The set of all the sessions
     */
    public static Hashtable conversationSessionTable = new Hashtable();

    /**
     * @param uuid 
     * @param info 
     */
    public static void addSecurtiyContext(String uuid,
                                          SecurityContextInfo info) {
        // Create a new conversation session and add it to the session list
        conversationSessionTable.put(uuid, new ConversationSession(info));
    }

    // 
    // /**
    // * <strong>This should not be used</strong>
    // * @param uuid
    // * @param dkt
    // */
    // public void addDerivedKeyToken(String uuid, DerivedKeyToken dkt) throws ConversationException{
    // this.addDerivedKey(uuid,new DerivedKeyInfo(dkt));
    // }

    /**
     * Adds a derived key into a session identified by the uuid
     * 
     * @param uuid   The uuid of the session
     * @param dkInfo The derived key as a <code>DerivedKeyInfo</code> object
     * @throws ConversationException If the uuid is not in the list of sessions
     *                               <b>This should be done here and not in the <code>handle</code> method since for example if the session is expired
     *                               the request should not pass this point</b>
     *                               In the scenario that we'r concerned here one party creates a derived key, encryps the message with it and sends
     *                               The receiver should decrypt the message with that derived key. Therefore if the session is expired
     *                               that fact will  be only evident at this point where, the derived key is being added into the relevant session.
     */
    public void addDerivedKey(String identifier, DerivedKeyInfo dkInfo)
            throws ConversationException {
		String[] arr = ConversationUtil.getUuidAndDerivedKeyTokenId(identifier);
		String uuid = arr[0];
        ConversationSession convSess =
                (ConversationSession) this.conversationSessionTable.get(uuid);
        if (convSess != null) {
            ((ConversationSession) this.conversationSessionTable.get(uuid)).addDerivedKey(dkInfo);
        } else {
            throw new ConversationException("The error not set yet : ref 1");

            /** @todo Handle this error properly */

            // This place can be reached
            // 1. If the session is expired
            // 2. If a wrong security context token is sent in (may be by some intruder)
            // 3. Will list more as and when I realize them :D
        }
    }

    /**
     * @param callbacks 
     * @throws UnsupportedCallbackException 
     */
    public void handle(Callback[] callbacks)
            throws UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];
            String keyId = pc.getIdentifer();

            // This will not be kept static
//            KeyDerivator kd = new KeyDerivator(true, 16);
//            try {
//                kd.generateKey(this.conversationSessionTable, keyId);
//            } catch (ConversationException ex1) {
//            } catch (WSSecurityException ex1) {
//            }
//
//            // KeyDerivator.generateKey(this.conversationSessionTable, keyId);
            pc.setPassword("security");

            /** Field key */
            byte[] key = {
                (byte) 0x31, (byte) 0xfd, (byte) 0xcb, (byte) 0xda, (byte) 0xfb,
                (byte) 0xcd, (byte) 0x6b, (byte) 0xa8, (byte) 0xe6, (byte) 0x19,
                (byte) 0xa7, (byte) 0xbf, (byte) 0x51, (byte) 0xf7, (byte) 0xc7,
                (byte) 0x3e, (byte) 0x80, (byte) 0xae, (byte) 0x98, (byte) 0x51,
                (byte) 0xc8, (byte) 0x51, (byte) 0x34, (byte) 0x04
            };
            pc.setKey(key);
        }
    }
}
