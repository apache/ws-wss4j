/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.impl.securityToken;

import org.swssf.crypto.Crypto;
import org.swssf.ext.Constants;
import org.swssf.ext.SecurityToken;
import org.swssf.ext.WSSecurityException;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.stream.events.XMLEvent;
import java.security.Key;
import java.security.PublicKey;
import java.util.Deque;

/**
 * @author $Author: $
 * @version $Revision: $ $Date: $
 */
public class SecurityTokenReference extends AbstractSecurityToken {

    private SecurityToken securityToken;
    private Deque<XMLEvent> xmlEvents;

    public SecurityTokenReference(SecurityToken securityToken, Deque<XMLEvent> xmlEvents, Crypto crypto, CallbackHandler callbackHandler) {
        super(crypto, callbackHandler);
        this.securityToken = securityToken;
        this.xmlEvents = xmlEvents;
    }

    public Deque<XMLEvent> getXmlEvents() {
        return xmlEvents;
    }

    public boolean isAsymmetric() {
        return securityToken.isAsymmetric();
    }

    public Key getSecretKey(String algorithmURI) throws WSSecurityException {
        return securityToken.getSecretKey(algorithmURI);
    }

    public PublicKey getPublicKey() throws WSSecurityException {
        return securityToken.getPublicKey();
    }

    public void verify() throws WSSecurityException {
        securityToken.verify();
    }

    public SecurityToken getKeyWrappingToken() {
        return securityToken.getKeyWrappingToken();
    }

    public String getKeyWrappingTokenAlgorithm() {
        return securityToken.getKeyWrappingTokenAlgorithm();
    }

    public Constants.KeyIdentifierType getKeyIdentifierType() {
        return securityToken.getKeyIdentifierType();
    }
}
