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
import java.util.NoSuchElementException;
import java.util.Set;

public final class ThreadLocalSecurityProvider extends Provider {

    private static final long serialVersionUID = 3556396671069994931L;
    private static final String NAME = "TLSP";
    private static final ThreadLocal<Provider> provider = new ThreadLocal<Provider>();
    private static boolean installed = false;
    private static final EmptyEnumeration<Object> emptyEnumeration = new EmptyEnumeration<Object>();

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
        provider.set(p);
    }

    public static void unsetProvider() {
        provider.remove();
    }

    private Provider getProvider() {
        return provider.get();
    }

    public void clear() {
        Provider p = getProvider();
        if (p != null) {
            p.clear();
        }
    }

    public void load(InputStream inStream) throws IOException {
        Provider p = getProvider();
        if (p != null) {
            p.load(inStream);
        }
    }

    public void putAll(Map<?, ?> t) {
        Provider p = getProvider();
        if (p != null) {
            p.putAll(t);
        }
    }

    public Set<Map.Entry<Object, Object>> entrySet() {
        Provider p = getProvider();
        if (p != null) {
            return p.entrySet();
        } else {
            return Collections.emptySet();
        }
    }

    public Set<Object> keySet() {
        Provider p = getProvider();
        if (p != null) {
            return p.keySet();
        } else {
            return Collections.emptySet();
        }
    }

    public Collection<Object> values() {
        Provider p = getProvider();
        if (p != null) {
            return p.values();
        } else {
            return Collections.emptyList();
        }
    }

    public Object put(Object key, Object value) {
        Provider p = getProvider();
        if (p != null) {
            return p.put(key, value);
        } else {
            return null;
        }
    }

    public Object remove(Object key) {
        Provider p = getProvider();
        if (p != null) {
            return p.remove(key);
        } else {
            return null;
        }
    }

    public Object get(Object key) {
        Provider p = getProvider();
        if (p != null) {
            return p.get(key);
        } else {
            return null;
        }
    }

    public Enumeration<Object> keys() {
        Provider p = getProvider();
        if (p != null) {
            return p.keys();
        } else {
            return emptyEnumeration;
        }
    }

    public Enumeration<Object> elements() {
        Provider p = getProvider();
        if (p != null) {
            return p.elements();
        } else {
            return emptyEnumeration;
        }
    }

    public String getProperty(String key) {
        Provider p = getProvider();
        if (p != null) {
            return p.getProperty(key);
        } else {
            return null;
        }
    }

    public Service getService(String type, String algorithm) {
        Provider p = getProvider();
        if (p != null) {
            return p.getService(type, algorithm);
        } else {
            return null;
        }
    }

    public Set<Service> getServices() {
        Provider p = getProvider();
        if (p != null) {
            return p.getServices();
        } else {
            return Collections.emptySet();
        }
    }

    private static class EmptyEnumeration<T> implements Enumeration<T> {

        @Override
        public boolean hasMoreElements() {
            return false;
        }

        @Override
        public T nextElement() {
            throw new NoSuchElementException();
        }

    }
}