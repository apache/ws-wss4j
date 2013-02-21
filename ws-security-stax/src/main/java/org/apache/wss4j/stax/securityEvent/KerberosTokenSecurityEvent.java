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
package org.apache.wss4j.stax.securityEvent;

import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.impl.securityToken.KerberosServiceSecurityToken;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class KerberosTokenSecurityEvent extends IssuedTokenSecurityEvent {

    private String issuerName;

    public KerberosTokenSecurityEvent() {
        super(WSSecurityEventConstants.KerberosToken);
    }

    public String getIssuerName() {
        return issuerName; //todo return ((KerberosServiceSecurityToken)getSecurityToken()).???();
    }

    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    public boolean isKerberosV5ApReqToken11() {
        String type = ((KerberosServiceSecurityToken)getSecurityToken()).getKerberosTokenValueType();
        if (WSSConstants.NS_Kerberos5_AP_REQ.equals(type)
                || WSSConstants.NS_Kerberos5_AP_REQ1510.equals(type)
                || WSSConstants.NS_Kerberos5_AP_REQ4120.equals(type)) {
            return true;
        }
        return false;
    }

    public boolean isGssKerberosV5ApReqToken11() {
        String type = ((KerberosServiceSecurityToken)getSecurityToken()).getKerberosTokenValueType();
        if (WSSConstants.NS_GSS_Kerberos5_AP_REQ.equals(type)
                || WSSConstants.NS_GSS_Kerberos5_AP_REQ1510.equals(type)
                || WSSConstants.NS_GSS_Kerberos5_AP_REQ4120.equals(type)) {
            return true;
        }
        return false;
    }

    public String getKerberosTokenValueType() {
        return ((KerberosServiceSecurityToken)getSecurityToken()).getKerberosTokenValueType();
    }
}
