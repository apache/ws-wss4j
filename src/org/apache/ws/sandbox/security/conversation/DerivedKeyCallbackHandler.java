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

/**
 * @author Ruchith Fernando
 * @version 1.0
 */

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.conversation.message.info.DerivedKeyInfo;
import org.apache.ws.security.conversation.message.info.SecurityContextInfo;
import org.apache.ws.security.conversation.sessions.SessionMonitor;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.util.Hashtable;

public class DerivedKeyCallbackHandler implements CallbackHandler {

    private static Log log = LogFactory.getLog(DerivedKeyCallbackHandler.class.getName());

    /**
     * The set of all the sessions
     */
    public static Hashtable conversationSessionTable = new Hashtable();

    static {
        log.debug("DerivedKeyCallbackHandler: Creating a session monitor");
        try {
            SessionMonitor sm = new SessionMonitor(conversationSessionTable);
            sm.start();
        } catch (ConversationException ex) {
            ex.printStackTrace();
        }
    }

    /**
     * @param uuid
     * @param info
     */
    public static void addSecurtiyContext(String uuid, SecurityContextInfo info) {
        //Create a new conversation session and add it to the session list
        log.debug("DerivedKeyCallbackHandler: adding security context. Identifier: " + uuid);
        conversationSessionTable.put(uuid, new ConversationSession(info));
    }

    /**
     * In cases where fixed size derived keys are used; this method can be used to
     * specifu the key size of a perticular session
     *
     * @param uuid      The identifier of the security context of the session
     * @param keyLength the desired key size
     * @throws ConversationException If the specified session is not available
     *                               (There can be sevral reasons for this : expiration etc. will have to look into this)
     */
    public static void setDerivedKeyLength(String uuid, long keyLength) throws
            ConversationException {
        log.debug("DerivedKeyCallbackHandler: setting derived key length: " + keyLength);
        ConversationSession session = (ConversationSession) conversationSessionTable.get(uuid);
        if (session != null) {
            session.setKeyLength(keyLength);
        } else {
            throw new ConversationException("The key size cannot be set: No such context/session");
        }

    }

    //Dimuthu's COnversation manager requires this method
    public static long getDerivedKeyLength(String uuid) throws ConversationException {
        ConversationSession session = (ConversationSession) conversationSessionTable.get(uuid);
        if (session != null) {
            return session.getKeyLength();
        } else {
            throw new ConversationException("The key size cannot be retrieved: No such context/session");
        }

    }

    /**
     * If the Label element is not available in a DerivedKeyToken element then
     * the value given here will be use in the key derivation
     * This value will be bound to the session. (There will be one label value for
     * the session and it should not change during a derivation sequence
     *
     * @param uuid  The identifier of the security context of the session
     * @param label The label value as a string
     * @throws ConversationException If the specified session is not available
     *                               (There can be sevral reasons for this : expiration etc. will have to look into this)
     */
    public static void setLabelForSession(String uuid, String label) throws
            ConversationException {
        ConversationSession session = (ConversationSession) conversationSessionTable.get(uuid);
        if (session != null) {
            session.setLabel(label);
        } else {
            throw new ConversationException("The key size cannot be set: No such context/session");
        }
    }

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
    public void addDerivedKey(String uuid, DerivedKeyInfo dkInfo) throws ConversationException {
        log.debug("DerivedKeyCallbackHandler: Adding derived key Id: " + dkInfo.getId() + " to session: " + uuid);
        ConversationSession convSess = (ConversationSession) conversationSessionTable.get(uuid);
        if (convSess != null) {
            ((ConversationSession) conversationSessionTable.get(uuid)).
                    addDerivedKey(dkInfo);
        } else {
            throw new ConversationException("Session cannot be found");
            /** @todo Handle this error properly  */
            //This place can be reached
            //1. If the session is expired
            //2. If a wrong security context token is sent in (may be by some intruder)
            //3. Will list more as and when I realize them :D
        }
    }

    /**
     * @param callbacks
     * @throws UnsupportedCallbackException
     */
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];

            String keyId = pc.getIdentifer();
            log.debug("DerivedKeyCallbackHandler: Requesting key for callback id: " + keyId);
            //This will not be kept static
            //Thisis instanciated all teh time
            //So if the keying information(fixed size or not) changes during the session that can be supported
            KeyDerivator kd = new KeyDerivator();
            try {
                pc.setKey(kd.generateKey(conversationSessionTable, keyId));
            } catch (ConversationException ex1) {
                ex1.printStackTrace();
            } catch (WSSecurityException ex1) {
                ex1.printStackTrace();
            }

//
//      pc.setPassword("security");
//      /** Field key */
//      byte[] key = {
//      (byte) 0x31, (byte) 0xfd, (byte) 0xcb, (byte) 0xda, (byte) 0xfb,
//      (byte) 0xcd, (byte) 0x6b, (byte) 0xa8, (byte) 0xe6, (byte) 0x19,
//      (byte) 0xa7, (byte) 0xbf, (byte) 0x51, (byte) 0xf7, (byte) 0xc7,
//      (byte) 0x3e, (byte) 0x80, (byte) 0xae, (byte) 0x98, (byte) 0x51,
//      (byte) 0xc8, (byte) 0x51, (byte) 0x34, (byte) 0x04};
//      pc.setKey(key);
//
        }
    }
}
