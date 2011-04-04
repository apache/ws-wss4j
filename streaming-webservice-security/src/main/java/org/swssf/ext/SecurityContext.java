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
package org.swssf.ext;

import org.swssf.securityEvent.SecurityEvent;
import org.swssf.securityEvent.SecurityEventListener;

import java.util.List;

/**
 * The document security context
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public interface SecurityContext {

    public <T> void put(String key, T value);

    public <T> T get(String key);

    public <T extends List> void putList(Class key, T value);

    public <T extends List> void putAsList(Class key, T value);

    public <T> List<T> getAsList(Class key);

    /**
     * Register a new SecurityTokenProvider.
     *
     * @param id                    A unique id
     * @param securityTokenProvider The actual SecurityTokenProvider to register.
     */
    public void registerSecurityTokenProvider(String id, SecurityTokenProvider securityTokenProvider);

    /**
     * Returns a registered SecurityTokenProvider with the given id or null if not found
     *
     * @param id The SecurityTokenProvider's id
     * @return The SecurityTokenProvider
     */
    public SecurityTokenProvider getSecurityTokenProvider(String id);

    /**
     * Registers a SecurityEventListener to receive Security-Events
     *
     * @param securityEventListener The SecurityEventListener
     */
    public void setSecurityEventListener(SecurityEventListener securityEventListener);

    /**
     * Registers a SecurityEvent which will be forwarded to the registered SecurityEventListener
     *
     * @param securityEvent The security event for the SecurityEventListener
     * @throws WSSecurityException when the event will not be accepted (e.g. policy-violation)
     */
    public void registerSecurityEvent(SecurityEvent securityEvent) throws WSSecurityException;
}
