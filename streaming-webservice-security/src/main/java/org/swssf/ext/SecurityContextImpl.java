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

import com.sun.istack.Nullable;
import org.swssf.securityEvent.SecurityEvent;
import org.swssf.securityEvent.SecurityEventListener;

import java.util.*;

/**
 * Concrete security context implementation
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class SecurityContextImpl implements SecurityContext {

    private Map<String, SecurityTokenProvider> secretTokenProviders = new HashMap<String, SecurityTokenProvider>();

    private SecurityEventListener securityEventListener;

    @SuppressWarnings("unchecked")
    private Map content = Collections.synchronizedMap(new HashMap());

    @SuppressWarnings("unchecked")
    public <T> void put(String key, T value) {
        content.put(key, value);
    }

    @SuppressWarnings("unchecked")
    public <T> T get(String key) {
        return (T) content.get(key);
    }

    @SuppressWarnings("unchecked")
    public <T> T remove(String key) {
        return (T) content.remove(key);
    }

    @SuppressWarnings("unchecked")
    public <T extends List> void putList(Class key, T value) {
        if (value == null) {
            return;
        }
        List<T> entry = (List<T>) content.get(key);
        if (entry == null) {
            entry = new ArrayList<T>();
            content.put(key, entry);
        }
        entry.addAll(value);
    }

    @SuppressWarnings("unchecked")
    public <T> void putAsList(Class key, T value) {
        List<T> entry = (List<T>) content.get(key);
        if (entry == null) {
            entry = new ArrayList<T>();
            content.put(key, entry);
        }
        entry.add(value);
    }

    @SuppressWarnings("unchecked")
    public <T> List<T> getAsList(Class key) {
        return (List<T>) content.get(key);
    }

    public void registerSecurityTokenProvider(String id, SecurityTokenProvider securityTokenProvider) {
        if (id == null) {
            throw new IllegalArgumentException("Id must not be null");
        }
        secretTokenProviders.put(id, securityTokenProvider);
    }

    public SecurityTokenProvider getSecurityTokenProvider(String id) {
        return secretTokenProviders.get(id);
    }

    public void setSecurityEventListener(@Nullable SecurityEventListener securityEventListener) {
        this.securityEventListener = securityEventListener;
    }

    public void registerSecurityEvent(SecurityEvent securityEvent) throws WSSecurityException {
        if (securityEventListener != null) {
            securityEventListener.registerSecurityEvent(securityEvent);
        }
    }
}
