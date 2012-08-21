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

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

/**
 * This class represents a PrivilegedAction implementation to obtain a service ticket from a Kerberos
 * Key Distribution Center.
 */
public class KerberosClientAction implements PrivilegedAction<byte[]> {
    private static org.apache.commons.logging.Log log =
        org.apache.commons.logging.LogFactory.getLog(KerberosClientAction.class);
    
    private Principal clientPrincipal;
    private String serviceName;
    
    public KerberosClientAction(Principal clientPrincipal, String serviceName) {
        this.clientPrincipal = clientPrincipal;
        this.serviceName = serviceName;
    }

    public byte[] run() {
        try {
            GSSManager gssManager = GSSManager.getInstance();
        
            Oid kerberos5Oid = new Oid("1.2.840.113554.1.2.2");
            GSSName gssClient = gssManager.createName(clientPrincipal.getName(), GSSName.NT_USER_NAME);
            GSSCredential credentials = 
                gssManager.createCredential(
                    gssClient, GSSCredential.DEFAULT_LIFETIME, kerberos5Oid, GSSCredential.INITIATE_ONLY
                );
            
            GSSName gssService = gssManager.createName(serviceName, GSSName.NT_HOSTBASED_SERVICE);
            GSSContext secContext =
                gssManager.createContext(
                    gssService, kerberos5Oid, credentials, GSSContext.DEFAULT_LIFETIME
                );
 
            secContext.requestMutualAuth(false);
            byte[] token = new byte[0];
            byte[] returnedToken = secContext.initSecContext(token, 0, token.length);
            secContext.dispose();
            return returnedToken;
        } catch (GSSException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error in obtaining a Kerberos token", e);
            }
        }

        return null;
        
    }
    
}
