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

package org.apache.wss4j.common.util;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Locale;

import org.apache.wss4j.common.ext.WSSecurityException;

/**
 * Load resources (or images) from various sources.
 * <p/>
 */
public final class Loader {

    /**
     * System property holding a comma-separated list of URL schemes that
     * {@link #loadInputStream(ClassLoader, String)} is allowed to open when a resource
     * string parses as a URL. The default is "file,jar": remote fetching of configured
     * resources (keystores, truststores, CRLs, properties files) over e.g. http is not
     * enabled unless explicitly configured. For a nested-URL scheme such as "jar"
     * (<code>jar:&lt;url&gt;!/&lt;entry&gt;</code>), the embedded URL must use an allowed
     * scheme as well: "jar:file:..." is permitted by default, "jar:http://..." is not.
     */
    public static final String ALLOWED_URL_SCHEMES_PROPERTY =
        "org.apache.wss4j.loader.allowedUrlSchemes";

    private static final String DEFAULT_ALLOWED_URL_SCHEMES = "file,jar";

    private static final org.slf4j.Logger LOG =
            org.slf4j.LoggerFactory.getLogger(Loader.class);

    private Loader() {
        // complete
    }

    /**
     * Load a resource as a stream. The resolution order is:
     * <ol>
     * <li>the file system - an existing file wins, so that a path configured by the
     * operator cannot be shadowed by a same-named classpath resource;</li>
     * <li>a URL, if the resource string parses as one and its scheme is in the allowed
     * list (see {@link #ALLOWED_URL_SCHEMES_PROPERTY}; "file" and "jar" by default) -
     * for a nested-URL scheme such as "jar", the embedded URL's scheme must also be in
     * the allowed list;</li>
     * <li>the classpath.</li>
     * </ol>
     * Note: prior to the introduction of this ordering, URLs (any scheme) and the
     * classpath were consulted before the file system.
     */
    public static InputStream loadInputStream(ClassLoader loader, String resource)
        throws WSSecurityException, IOException {
        InputStream is = null;
        if (resource != null) {
            //
            // First look on the file system
            //
            Path path = null;
            try {
                path = Paths.get(resource);
            } catch (InvalidPathException ex) { //NOPMD
                // skip - not a valid file system path
            }
            if (path != null && Files.exists(path)) {
                try {
                    return Files.newInputStream(path);
                } catch (Exception e) {
                    LOG.debug(e.getMessage(), e);
                    throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILURE, e, "resourceNotFound", new Object[] {resource}
                    );
                }
            }

            // Next see if it's a URL with an allowed scheme
            URL url = null;
            try {
                url = new URL(resource);
            } catch (MalformedURLException ex) { //NOPMD
                // skip
            }
            String disallowedScheme = url == null ? null : findDisallowedScheme(url);
            if (disallowedScheme != null) {
                LOG.warn("Not loading resource [" + resource + "]: URL scheme \"" + disallowedScheme
                    + "\" is not allowed. Set the " + ALLOWED_URL_SCHEMES_PROPERTY
                    + " system property to permit additional schemes.");
                url = null;
            }
            // If not a (permitted) URL, then try to load the resource from the classpath
            if (url == null) {
                url = Loader.getResource(loader, resource);
            }
            if (url != null) {
                is = url.openStream();
            }

            if (is == null) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, "resourceNotFound", new Object[] {resource}
                );
            }
        }
        return is;
    }

    /**
     * Return the scheme that prevents <code>url</code> from being opened, or null if the
     * URL only uses allowed schemes. For a nested-URL scheme such as "jar"
     * (<code>jar:&lt;url&gt;!/&lt;entry&gt;</code>), the embedded URL is validated
     * recursively, so e.g. "jar:http://..." is refused unless "http" is itself allowed.
     * A nested part that is missing or does not parse as a URL is refused (fail closed).
     */
    private static String findDisallowedScheme(URL url) {
        String scheme = url.getProtocol();
        if (!isAllowedUrlScheme(scheme)) {
            return scheme;
        }
        if ("jar".equals(scheme.toLowerCase(Locale.ROOT))) {
            // A jar URL nests another URL: everything after "jar:" and before "!/" is
            // itself a URL that a JarURLConnection would fetch (an outbound request for
            // e.g. jar:http://...). Validate the nested URL's scheme as well.
            String spec = url.getFile();
            int separator = spec.indexOf("!/");
            if (separator < 0) {
                return scheme;
            }
            URL nestedUrl;
            try {
                nestedUrl = new URL(spec.substring(0, separator).trim());
            } catch (MalformedURLException ex) { //NOPMD
                return scheme;
            }
            return findDisallowedScheme(nestedUrl);
        }
        return null;
    }

    private static boolean isAllowedUrlScheme(String scheme) {
        if (scheme == null) {
            return false;
        }
        String allowedSchemes = System.getProperty(ALLOWED_URL_SCHEMES_PROPERTY, DEFAULT_ALLOWED_URL_SCHEMES);
        for (String allowed : allowedSchemes.split(",")) {
            if (scheme.toLowerCase(Locale.ROOT).equals(allowed.trim().toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    /**
     * This method will search for <code>resource</code> in different
     * places. The search order is as follows:
     * <ol>
     * <p><li>Search for <code>resource</code> using the thread context
     * class loader under Java2.
     * <p><li>Try one last time with
     * <code>ClassLoader.getSystemResource(resource)</code>, that is is
     * using the system class loader in JDK 1.2 and virtual machine's
     * built-in class loader in JDK 1.1.
     * </ol>
     * <p/>
     *
     * @param resource
     * @return the url to the resource or null if not found
     */
    public static URL getResource(String resource) {
        URL url = null;
        try {
            ClassLoader classLoader = getTCL();
            if (classLoader != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Trying to find [" + resource + "] using " + classLoader + " class loader.");
                }
                url = classLoader.getResource(resource);
                if (url == null && resource.startsWith("/")) {
                    //certain classloaders need it without the leading /
                    url = classLoader.getResource(resource.substring(1));
                }
                if (url != null) {
                    return url;
                }
            }
        } catch (Exception e) {
            LOG.warn("Caught Exception while in Loader.getResource. This may be innocuous.", e);
        }

        ClassLoader cluClassloader = Loader.class.getClassLoader();
        if (cluClassloader == null) {
            cluClassloader = ClassLoader.getSystemClassLoader();
        }
        url = cluClassloader.getResource(resource);
        if (url == null && resource.startsWith("/")) {
            //certain classloaders need it without the leading /
            url = cluClassloader.getResource(resource.substring(1));
        }
        if (url != null) {
            return url;
        }

        // Last ditch attempt: get the resource from the class path. It
        // may be the case that clazz was loaded by the Extension class
        // loader which the parent of the system class loader. Hence the
        // code below.
        LOG.debug("Trying to find [{}] using ClassLoader.getSystemResource().", resource);
        return ClassLoader.getSystemResource(resource);
    }


    /**
     * This method will search for <code>resource</code> in different
     * places. The search order is as follows:
     * <ol>
     * <p><li>Search for <code>resource</code> using the supplied class loader.
     * If that fails, search for <code>resource</code> using the thread context
     * class loader.
     * <p><li>Try one last time with
     * <code>ClassLoader.getSystemResource(resource)</code>, that is is
     * using the system class loader in JDK 1.2 and virtual machine's
     * built-in class loader in JDK 1.1.
     * </ol>
     * <p/>
     *
     * @param resource
     * @return the url to the resource or null if not found
     */
    public static URL getResource(ClassLoader loader, String resource) {
        URL url = null;
        try {
            if (loader != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Trying to find [" + resource + "] using " + loader + " class loader.");
                }
                url = loader.getResource(resource);
                if (url == null && resource.startsWith("/")) {
                    //certain classloaders need it without the leading /
                    url = loader.getResource(resource.substring(1));
                }
                if (url != null) {
                    return url;
                }
            }
        } catch (Exception e) {
            LOG.warn("Caught Exception while in Loader.getResource. This may be innocuous.", e);
        }
        return getResource(resource);
    }

    /**
     * This is a convenience method to load a resource as a stream. <p/> The
     * algorithm used to find the resource is given in getResource()
     *
     * @param resourceName The name of the resource to load
     */
    public static InputStream getResourceAsStream(String resourceName) {
        URL url = getResource(resourceName);

        try {
            return (url != null) ? url.openStream() : null;
        } catch (IOException e) {
            LOG.debug(e.getMessage(), e);
            return null;
        }
    }

    /**
     * Get the Thread context class loader.
     * <p/>
     *
     * @return the Thread context class loader
     * @throws IllegalAccessException
     * @throws InvocationTargetException
     */
    public static ClassLoader getTCL() throws IllegalAccessException, InvocationTargetException {
        return AccessController.doPrivileged(new PrivilegedAction<ClassLoader>() {
            public ClassLoader run() {
                return Thread.currentThread().getContextClassLoader();
            }
        });
    }

    /**
     * Get the class loader of the class argument
     * <p/>
     *
     * @return the class loader of the argument
     */
    public static ClassLoader getClassLoader(final Class<?> clazz) {
        return AccessController.doPrivileged(new PrivilegedAction<ClassLoader>() {
            public ClassLoader run() {
                return clazz.getClassLoader();
            }
        });
    }

    /**
     * Try the specified classloader and then fall back to the loadClass
     * <p/>
     *
     * @param loader
     * @param clazz
     * @return Class
     * @throws ClassNotFoundException
     */
    public static Class<?> loadClass(ClassLoader loader, String clazz) throws ClassNotFoundException {
        try {
            if (loader != null) {
                Class<?> c = loader.loadClass(clazz);
                if (c != null) {
                    return c;
                }
            }
        } catch (Exception e) {
            LOG.warn(e.getMessage(), e);
        }
        return loadClass(clazz, true);
    }

    /**
     * Try the specified classloader and then fall back to the loadClass
     * <p/>
     *
     * @param loader
     * @param clazz
     * @param type
     * @return Class
     * @throws ClassNotFoundException
     */
    public static <T> Class<? extends T> loadClass(ClassLoader loader,
                                                   String clazz,
                                                   Class<T> type) throws ClassNotFoundException {
        try {
            if (loader != null) {
                Class<?> c = loader.loadClass(clazz);
                if (c != null) {
                    return c.asSubclass(type);
                }
            }
        } catch (Exception e) {
            LOG.warn(e.getMessage(), e);
        }
        return loadClass(clazz, true, type);
    }

    /**
     * If running under JDK 1.2 load the specified class using the
     * <code>Thread</code> <code>contextClassLoader</code> if that
     * fails try Class.forname.
     * <p/>
     *
     * @param clazz
     * @return the class
     * @throws ClassNotFoundException
     */
    public static Class<?> loadClass(String clazz) throws ClassNotFoundException {
        return loadClass(clazz, true);
    }

    /**
     * If running under JDK 1.2 load the specified class using the
     * <code>Thread</code> <code>contextClassLoader</code> if that
     * fails try Class.forname.
     * <p/>
     *
     * @param clazz
     * @param type  Type to cast it to
     * @return the class
     * @throws ClassNotFoundException
     */
    public static <T> Class<? extends T> loadClass(String clazz, Class<T> type)
            throws ClassNotFoundException {
        return loadClass(clazz, true, type);
    }

    public static <T> Class<? extends T> loadClass(String clazz,
                                                   boolean warn,
                                                   Class<T> type) throws ClassNotFoundException {
        return loadClass(clazz, warn).asSubclass(type);
    }

    public static Class<?> loadClass(String clazz, boolean warn) throws ClassNotFoundException {
        try {
            ClassLoader tcl = getTCL();

            if (tcl != null) {
                Class<?> c = tcl.loadClass(clazz);
                if (c != null) {
                    return c;
                }
            }
        } catch (Exception e) {
            if (warn) {
                LOG.warn(e.getMessage(), e);
            } else {
                LOG.debug(e.getMessage(), e);
            }
        }

        return loadClass2(clazz, null);
    }

    private static Class<?> loadClass2(String className, Class<?> callingClass)
        throws ClassNotFoundException {
        try {
            return Class.forName(className);
        } catch (ClassNotFoundException ex) {
            try {
                if (Loader.class.getClassLoader() != null) {
                    return Loader.class.getClassLoader().loadClass(className);
                }
            } catch (ClassNotFoundException exc) {
                if (callingClass != null && callingClass.getClassLoader() != null) {
                    return callingClass.getClassLoader().loadClass(className);
                }
            }
            throw ex;
        }
    }
}
