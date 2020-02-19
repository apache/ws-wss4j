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
package org.apache.wss4j.common.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.security.Provider;
import java.security.Security;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;
import java.util.Set;

public final class ThreadLocalSecurityProvider extends Provider {

    private static final long serialVersionUID = 3556396671069994931L;
    private static final String NAME = "TLSP";
    private static final ThreadLocal<Provider> PROVIDER = new ThreadLocal<>();
    private static boolean installed = false;

    public static synchronized void install() {
        Security.insertProviderAt(new ThreadLocalSecurityProvider(),
                Security.getProviders().length);
        installed = true;
    }

    public static synchronized void uninstall() {
        Security.removeProvider(NAME);
        installed = false;
    }

    public static boolean isInstalled() {
        return installed;
    }

    private ThreadLocalSecurityProvider() {
        super(NAME, 1.00, "ThreadLocal Security Provider");
    }

    public static void setProvider(Provider p) {
        PROVIDER.set(p);
    }

    public static void unsetProvider() {
        PROVIDER.remove();
    }

    private Provider getProvider() {
        return PROVIDER.get();
    }

    @Override
    public synchronized void clear() {
        Provider p = getProvider();
        if (p != null) {
            p.clear();
        }
    }

    @Override
    public synchronized void load(InputStream inStream) throws IOException {
        Provider p = getProvider();
        if (p != null) {
            p.load(inStream);
        }
    }

    @Override
    public synchronized void putAll(Map<?, ?> t) {
        Provider p = getProvider();
        if (p != null) {
            p.putAll(t);
        }
    }

    @Override
    public synchronized Set<Map.Entry<Object, Object>> entrySet() {
        Provider p = getProvider();
        if (p != null) {
            return p.entrySet();
        } else {
            return Collections.emptySet();
        }
    }

    @Override
    public Set<Object> keySet() {
        Provider p = getProvider();
        if (p != null) {
            return p.keySet();
        } else {
            return Collections.emptySet();
        }
    }

    @Override
    public Collection<Object> values() {
        Provider p = getProvider();
        if (p != null) {
            return p.values();
        } else {
            return Collections.emptyList();
        }
    }

    @Override
    public synchronized Object put(Object key, Object value) {
        Provider p = getProvider();
        if (p != null) {
            return p.put(key, value);
        } else {
            return null;
        }
    }

    @Override
    public synchronized Object remove(Object key) {
        Provider p = getProvider();
        if (p != null) {
            return p.remove(key);
        } else {
            return null;
        }
    }

    @Override
    public Object get(Object key) {
        Provider p = getProvider();
        if (p != null) {
            return p.get(key);
        } else {
            return null;
        }
    }

    @Override
    public Enumeration<Object> keys() {
        Provider p = getProvider();
        if (p != null) {
            return p.keys();
        } else {
            return Collections.emptyEnumeration();
        }
    }

    @Override
    public Enumeration<Object> elements() {
        Provider p = getProvider();
        if (p != null) {
            return p.elements();
        } else {
            return Collections.emptyEnumeration();
        }
    }

    @Override
    public String getProperty(String key) {
        Provider p = getProvider();
        if (p != null) {
            return p.getProperty(key);
        } else {
            return null;
        }
    }

    @Override
    public synchronized Service getService(String type, String algorithm) {
        Provider p = getProvider();
        if (p != null) {
            return p.getService(type, algorithm);
        } else {
            return null;
        }
    }

    @Override
    public synchronized Set<Service> getServices() {
        Provider p = getProvider();
        if (p != null) {
            return p.getServices();
        } else {
            return Collections.emptySet();
        }
    }

}