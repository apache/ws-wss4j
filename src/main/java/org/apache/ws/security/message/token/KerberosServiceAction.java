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

import java.security.Principal;
import java.security.PrivilegedAction;

/**
 * This class represents a PrivilegedAction implementation to validate a received ticket to a KDC.
 */
public class KerberosServiceAction implements PrivilegedAction<Principal> {
    private static org.apache.commons.logging.Log LOG =
        org.apache.commons.logging.LogFactory.getLog(KerberosServiceAction.class);
    
    private byte[] ticket;
    private String serviceName;
    private boolean isUsernameServiceNameForm;
    
    public KerberosServiceAction(byte[] ticket, String serviceName) {
        this(ticket, serviceName, false);
    }
    
    public KerberosServiceAction(byte[] ticket, String serviceName, boolean isUsernameServiceNameForm) {
        this.ticket = ticket;
        this.serviceName = serviceName;
        this.isUsernameServiceNameForm = isUsernameServiceNameForm;
    }

    public Principal run() {
        try {
            KerberosServiceExceptionAction action = 
                new KerberosServiceExceptionAction(this.ticket, this.serviceName, this.isUsernameServiceNameForm);            
            KerberosServiceContext krbServiceCtx = action.run();            
            return krbServiceCtx.getPrincipal();
        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error in validating a Kerberos token", e);
            }
        }

        return null;
        
    }
    
}
