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

import java.security.Principal;
import java.security.PrivilegedAction;

/**
 * This class represents a PrivilegedAction implementation to obtain a service ticket from a Kerberos
 * Key Distribution Center.
 */
public class KerberosClientAction implements PrivilegedAction<byte[]> {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(KerberosClientAction.class);

    private Principal clientPrincipal;
    private String serviceName;
    private boolean isUsernameServiceNameForm;

    public KerberosClientAction(Principal clientPrincipal, String serviceName) {
        this(clientPrincipal, serviceName, false);
    }

    public KerberosClientAction(Principal clientPrincipal, String serviceName, boolean isUsernameServiceNameForm) {
        this.clientPrincipal = clientPrincipal;
        this.serviceName = serviceName;
        this.isUsernameServiceNameForm = isUsernameServiceNameForm;
    }

    public byte[] run() {
        try {
            KerberosContext krbCtx =
                (KerberosContext)new KerberosClientExceptionAction(clientPrincipal, serviceName,
                                                                   isUsernameServiceNameForm, false).run();
            return krbCtx.getKerberosToken();
        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error in obtaining a Kerberos token", e);
            }
        }

        return null;

    }

}
