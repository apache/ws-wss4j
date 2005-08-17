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

package org.apache.ws.sandbox.security.conversation.dkalgo;

import org.apache.ws.sandbox.security.conversation.ConversationException;

public interface DerivationAlgorithm {

    /**
     * This is the default key generation algotithm
     */
    public static final String P_SHA_1 = "http://schemas.xmlsoap.org/ws/2004/04/security/sc/dk/p_sha1";

    /**
     * @param secret
     * @param labelAndNonce
     * @param length
     * @return
     */
    public byte[] createKey(byte[] secret, String labelAndNonce, int offset, long length) throws ConversationException;

}
