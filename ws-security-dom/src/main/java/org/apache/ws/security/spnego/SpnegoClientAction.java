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

package org.apache.ws.security.spnego;

import java.security.PrivilegedAction;

import org.ietf.jgss.GSSContext;

/**
 * This interface represents a PrivilegedAction implementation to obtain a (SPNEGO) service ticket 
 * from a Kerberos Key Distribution Center.
 */
public interface SpnegoClientAction extends PrivilegedAction<byte[]> {
    
    /**
     * Whether to enable mutual authentication or not.
     */
    void setMutualAuth(boolean mutualAuthentication);
    
    /**
     * The Service Name
     */
    void setServiceName(String serviceName);

    /**
     * Obtain a service ticket
     */
    byte[] run();
    
    /**
     * Get the GSSContext that was created after a service ticket was obtained
     */
    GSSContext getContext();
    
}
