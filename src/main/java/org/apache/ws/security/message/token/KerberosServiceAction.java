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

import javax.security.auth.kerberos.KerberosPrincipal;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

/**
 * This class represents a PrivilegedAction implementation to validate a received ticket to a KDC.
 */
public class KerberosServiceAction implements PrivilegedAction<Principal> {
    private static org.apache.commons.logging.Log log =
        org.apache.commons.logging.LogFactory.getLog(KerberosServiceAction.class);
    
    private byte[] ticket;
    private String serviceName;
    
    public KerberosServiceAction(byte[] ticket, String serviceName) {
        this.ticket = ticket;
        this.serviceName = serviceName;
    }

    public Principal run() {
        try {
            GSSManager gssManager = GSSManager.getInstance();
        
            Oid kerberos5Oid = new Oid("1.2.840.113554.1.2.2");
            GSSName gssService = gssManager.createName(serviceName, GSSName.NT_HOSTBASED_SERVICE);
            GSSCredential credentials = 
                gssManager.createCredential(
                    gssService, GSSCredential.DEFAULT_LIFETIME, kerberos5Oid, GSSCredential.ACCEPT_ONLY
                );
            
            GSSContext secContext =
                gssManager.createContext(credentials);
            secContext.acceptSecContext(ticket, 0, ticket.length);
 
            GSSName clientName = secContext.getSrcName();
            secContext.dispose();
            return new KerberosPrincipal(clientName.toString());
        } catch (GSSException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error in validating a Kerberos token", e);
            }
        }

        return null;
        
    }
    
}
