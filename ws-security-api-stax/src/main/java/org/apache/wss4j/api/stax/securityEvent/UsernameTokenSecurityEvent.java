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
package org.apache.wss4j.api.stax.securityEvent;

import org.apache.wss4j.api.stax.securityToken.UsernameSecurityToken;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;
import org.apache.wss4j.api.stax.ext.WSSConstants;

public class UsernameTokenSecurityEvent extends TokenSecurityEvent<UsernameSecurityToken> {

    private String usernameTokenProfile;

    public UsernameTokenSecurityEvent() {
        super(WSSecurityEventConstants.USERNAME_TOKEN);
    }

    public WSSConstants.UsernameTokenPasswordType getUsernameTokenPasswordType() {
        return getSecurityToken().getUsernameTokenPasswordType();
    }

    public String getUsernameTokenProfile() {
        return usernameTokenProfile;
    }

    public void setUsernameTokenProfile(String usernameTokenProfile) {
        this.usernameTokenProfile = usernameTokenProfile;
    }
}
