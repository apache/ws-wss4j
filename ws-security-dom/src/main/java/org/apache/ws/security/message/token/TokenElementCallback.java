/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.ws.security.message.token;

import org.w3c.dom.Element;

import javax.security.auth.callback.Callback;

/**
 * This class is a callback to obtain a DOM Element representing a security token.
 */
public class TokenElementCallback implements Callback {
    
    /**
     * A DOM Element representing a security token
     */
    private Element element;
    
    /**
     * Get the token element
     * @return the token element
     */
    public Element getTokenElement() {
        return element;
    }

    /**
     * Set the token element
     * @param element the token element
     */
    public void setTokenElement(Element element) {
        this.element = element;
    }
    
}
