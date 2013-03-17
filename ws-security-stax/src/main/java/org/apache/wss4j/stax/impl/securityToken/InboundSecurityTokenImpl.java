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
package org.apache.wss4j.stax.impl.securityToken;

import org.apache.wss4j.stax.ext.InboundSecurityToken;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.SecurityContext;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.impl.securityToken.AbstractInboundSecurityToken;

import javax.security.auth.Subject;
import java.security.Principal;

public abstract class InboundSecurityTokenImpl extends AbstractInboundSecurityToken implements InboundSecurityToken {

    private Subject subject;
    private Principal principal;

    protected InboundSecurityTokenImpl(SecurityContext securityContext, String id,
                                       XMLSecurityConstants.KeyIdentifierType keyIdentifierType) {
        super(securityContext, id, keyIdentifierType);
    }

    public void setSubject(Subject subject) {
        this.subject = subject;
    }

    @Override
    public Subject getSubject() throws XMLSecurityException {
        return subject;
    }

    public void setPrincipal(Principal principal) {
        this.principal = principal;
    }

    @Override
    public Principal getPrincipal() throws XMLSecurityException {
        return principal;
    }
}
