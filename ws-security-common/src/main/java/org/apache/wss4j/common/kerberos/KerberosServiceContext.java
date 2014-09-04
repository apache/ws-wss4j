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
package org.apache.wss4j.common.kerberos;

import java.security.Key;
import java.security.Principal;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;


public class KerberosServiceContext {
    
    private Principal principal;
    private Key sessionKey;
    private GSSCredential delegationCredential;
    private GSSContext gssContext;
    private byte[] kerberosToken;
    
    /**
     * @return the principal
     */
    public Principal getPrincipal() {
        return principal;
    }
    
    /**
     * @param principal the principal to set
     */
    public void setPrincipal(Principal principal) {
        this.principal = principal;
    }
    
    /**
     * @return the sessionKey
     */
    public Key getSessionKey() {
        return sessionKey;
    }
    
    /**
     * @param sessionKey the sessionKey to set
     */
    public void setSessionKey(Key sessionKey) {
        this.sessionKey = sessionKey;
    }

    public GSSCredential getDelegationCredential() {
        return delegationCredential;
    }

    public void setDelegationCredential(GSSCredential delegationCredential) {
        this.delegationCredential = delegationCredential;
    }

    public GSSContext getGssContext() {
        return gssContext;
    }

    public void setGssContext(GSSContext gssContext) {
        this.gssContext = gssContext;
    }

    public byte[] getKerberosToken() {
        return kerberosToken;
    }

    public void setKerberosToken(byte[] kerberosToken) {
        this.kerberosToken = kerberosToken;
    }
    
}
