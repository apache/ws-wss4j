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
package org.swssf.wss.ext;


import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.SecurityEventListener;
import org.swssf.xmlsec.ext.SecurityContext;

/**
 * The document security context
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public interface WSSecurityContext extends SecurityContext {

    /**
     * Registers a SecurityEventListener to receive Security-Events
     *
     * @param securityEventListener The SecurityEventListener
     */
    public void setSecurityEventListener(SecurityEventListener securityEventListener);

    /**
     * Registers a SecurityEvent which will be forwarded to the registered SecurityEventListener
     *
     * @param securityEvent The security event for the SecurityEventListener
     * @throws WSSecurityException when the event will not be accepted (e.g. policy-violation)
     */
    public void registerSecurityEvent(SecurityEvent securityEvent) throws WSSecurityException;
}
