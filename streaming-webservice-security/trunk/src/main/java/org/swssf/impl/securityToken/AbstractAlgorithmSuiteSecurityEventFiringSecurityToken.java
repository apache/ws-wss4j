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
import org.swssf.ext.SecurityContext;
import org.swssf.ext.WSSecurityException;
import org.swssf.securityEvent.AlgorithmSuiteSecurityEvent;
import org.swssf.securityEvent.SecurityEvent;

import javax.security.auth.callback.CallbackHandler;
import java.security.Key;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * @author $Author: $
 * @version $Revision: $ $Date: $
 */
public abstract class AbstractAlgorithmSuiteSecurityEventFiringSecurityToken extends AbstractSecurityToken {

    private boolean fireSecretKeySecurityEvent = true;
    private boolean firePublicKeySecurityEvent = true;
    private Map<String, Constants.KeyUsage> firedSecretKeyAlgorithmEvents = new HashMap<String, Constants.KeyUsage>();

    private SecurityContext securityContext;

    public AbstractAlgorithmSuiteSecurityEventFiringSecurityToken(SecurityContext securityContext, Crypto crypto, CallbackHandler callbackHandler, String id, Object processor) {
        super(crypto, callbackHandler, id, processor);
        this.securityContext = securityContext;
    }

    public AbstractAlgorithmSuiteSecurityEventFiringSecurityToken(SecurityContext securityContext, String id, Object processor) {
        super(null, null, id, processor);
        this.securityContext = securityContext;
    }

    public AbstractAlgorithmSuiteSecurityEventFiringSecurityToken(SecurityContext securityContext, String id) {
        super(id);
        this.securityContext = securityContext;
    }

    public Key getSecretKey(String algorithmURI, Constants.KeyUsage keyUsage) throws WSSecurityException {
        if (fireSecretKeySecurityEvent) {
            Constants.KeyUsage firedKeyUsage = firedSecretKeyAlgorithmEvents.get(algorithmURI);
            if (keyUsage == null || firedKeyUsage != keyUsage) {
                AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent(SecurityEvent.Event.AlgorithmSuite);
                algorithmSuiteSecurityEvent.setAlgorithmURI(algorithmURI);
                algorithmSuiteSecurityEvent.setKeyUsage(keyUsage);
                securityContext.registerSecurityEvent(algorithmSuiteSecurityEvent);
                firedSecretKeyAlgorithmEvents.put(algorithmURI, keyUsage);
            }
        }
        return null;
    }

    public PublicKey getPublicKey(Constants.KeyUsage keyUsage) throws WSSecurityException {
        return null;
    }
}
