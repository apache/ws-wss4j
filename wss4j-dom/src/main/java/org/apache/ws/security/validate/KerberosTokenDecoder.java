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

package org.apache.ws.security.validate;

import javax.security.auth.Subject;

/**
 * This interface defines a pluggable way to obtain a session key given an AP-REQ Kerberos token and a 
 * Subject. The session key is needed on the receiving side when it is used for message signature or
 * encryption. A default implementation is not shipped with WSS4J due to a dependency on internal APIs 
 * or ASN1 parsers.
 */
public interface KerberosTokenDecoder {
    
    /**
     * Set the AP-REQ Kerberos Token
     * @param token the AP-REQ Kerberos Token
     */
    void setToken(byte[] token);
    
    /**
     * Set the Subject
     * @param subject the Subject
     */
    void setSubject(Subject subject);
    
    /**
     * Get the session key from the token
     * @return the session key from the token
     */
    byte[] getSessionKey();
    
    /**
     * Clear all internal information
     */
    void clear();
    
}
