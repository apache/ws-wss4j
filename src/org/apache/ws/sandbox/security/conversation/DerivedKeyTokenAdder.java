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

import org.apache.ws.security.conversation.message.token.DerivedKeyToken;
import org.apache.ws.security.message.WSBaseMessage;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Class DerivedKeyTokenAdder
 */
public class DerivedKeyTokenAdder extends WSBaseMessage {

    /**
     * Method build
     *
     * @param doc
     * @param dkToken
     * @return
     */
    public Document build(Document doc,
                          DerivedKeyToken dkToken) {    // throws Exception {

        // log.debug("Begin add username token...");
        Element securityHeader = insertSecurityHeader(doc);
        WSSecurityUtil.prependChildElement(doc, securityHeader,
                dkToken.getElement(),false);
        return doc;
    }
}
