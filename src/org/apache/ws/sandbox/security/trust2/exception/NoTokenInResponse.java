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

package org.apache.ws.security.trust2.exception;

/**
 * @author ddelvecc
 *         <p/>
 *         An exception to indicate that a <RequestSecurityTokenResponse> message does not contain either a RequestedSecurityToken
 *         or RequestedProofToken element. WS-Trust requires at least one of the two.
 */
public class NoTokenInResponse extends TrustException {
    public NoTokenInResponse(String message) {
        super(message);
    }

}
