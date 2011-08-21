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
package org.swssf.ext;

import com.sun.istack.Nullable;
import org.swssf.securityEvent.SecurityEvent;
import org.swssf.securityEvent.SecurityEventListener;

import java.util.*;

/**
 * Concrete security context implementation
 *
 * @author $Author$
 * @version $Revision$ $Date$
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

    public synchronized void registerSecurityEvent(SecurityEvent securityEvent) throws WSSecurityException {
        if (securityEventListener != null) {
            securityEventListener.registerSecurityEvent(securityEvent);
        }
    }
}
