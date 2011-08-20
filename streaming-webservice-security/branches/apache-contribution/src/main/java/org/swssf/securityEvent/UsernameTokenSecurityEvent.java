/**
 * Copyright 2010, 2011 Marc Giger
 *
 * This file is part of the streaming-webservice-security-framework (swssf).
 *
 * The streaming-webservice-security-framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The streaming-webservice-security-framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the streaming-webservice-security-framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.securityEvent;

import org.swssf.ext.Constants;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class UsernameTokenSecurityEvent extends TokenSecurityEvent {

    private Constants.UsernameTokenPasswordType usernameTokenPasswordType;
    private String usernameTokenProfile;

    public UsernameTokenSecurityEvent(Event securityEventType) {
        super(securityEventType);
    }

    public Constants.UsernameTokenPasswordType getUsernameTokenPasswordType() {
        return usernameTokenPasswordType;
    }

    public void setUsernameTokenPasswordType(Constants.UsernameTokenPasswordType usernameTokenPasswordType) {
        this.usernameTokenPasswordType = usernameTokenPasswordType;
    }

    public String getUsernameTokenProfile() {
        return usernameTokenProfile;
    }

    public void setUsernameTokenProfile(String usernameTokenProfile) {
        this.usernameTokenProfile = usernameTokenProfile;
    }
}
