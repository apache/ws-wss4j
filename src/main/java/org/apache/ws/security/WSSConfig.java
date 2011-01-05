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


package org.apache.ws.security;

import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import javax.xml.namespace.QName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.action.Action;
import org.apache.ws.security.processor.Processor;
import org.apache.ws.security.util.Loader;
import org.apache.ws.security.util.UUIDGenerator;

/**
 * WSSConfig <p/> Carries configuration data so the WSS4J spec compliance can be
 * modified in runtime. Configure an instance of this object only if you need
 * WSS4J to emulate certain industry clients or previous OASIS specifications
 * for WS-Security interoperability testing purposes. <p/> The default settings
 * follow the latest OASIS and changing anything might violate the OASIS specs.
 * <p/> <b>WARNING: changing the default settings will break the compliance with
 * the latest specs. Do this only if you know what you are doing.</b> <p/>
 * 
 * @author Rami Jaamour (rjaamour@parasoft.com)
 * @author Werner Dittmann (werner@apache.org)
 */
public class WSSConfig {
    
    private static final Log log = LogFactory.getLog(WSSConfig.class.getName());

    /**
     * The default collection of actions supported by the toolkit.
     */
    private static final Map<Integer, Class<?>> DEFAULT_ACTIONS;
    static {
        final Map<Integer, Class<?>> tmp = new HashMap<Integer, Class<?>>();
        try {
            tmp.put(
                new Integer(WSConstants.UT),
                org.apache.ws.security.action.UsernameTokenAction.class
            );
            tmp.put(
                new Integer(WSConstants.ENCR),
                org.apache.ws.security.action.EncryptionAction.class
            );
            tmp.put(
                new Integer(WSConstants.SIGN),
                org.apache.ws.security.action.SignatureAction.class
            );
            tmp.put(
                new Integer(WSConstants.ST_SIGNED),
                org.apache.ws.security.action.SAMLTokenSignedAction.class
            );
            tmp.put(
                new Integer(WSConstants.ST_UNSIGNED),
                org.apache.ws.security.action.SAMLTokenUnsignedAction.class
            );
            tmp.put(
                new Integer(WSConstants.TS),
                org.apache.ws.security.action.TimestampAction.class
            );
            tmp.put(
                new Integer(WSConstants.UT_SIGN),
                org.apache.ws.security.action.UsernameTokenSignedAction.class
            );
            tmp.put(
                new Integer(WSConstants.SC),
                org.apache.ws.security.action.SignatureConfirmationAction.class
            );
        } catch (final Throwable t) {
            if (log.isDebugEnabled()) {
                log.debug(t.getMessage(), t);
            }
        }
        DEFAULT_ACTIONS = java.util.Collections.unmodifiableMap(tmp);
    }

    /**
     * The default collection of processors supported by the toolkit
     */
    private static final Map<QName, Class<?>> DEFAULT_PROCESSORS;
    static {
        final Map<QName, Class<?>> tmp = new HashMap<QName, Class<?>>();
        try {
            tmp.put(
                WSSecurityEngine.SAML_TOKEN,
                org.apache.ws.security.processor.SAMLTokenProcessor.class
            );
            tmp.put(
                WSSecurityEngine.SAML2_TOKEN,
                org.apache.ws.security.processor.SAMLTokenProcessor.class
            );
            tmp.put(
                WSSecurityEngine.ENCRYPTED_KEY,
                org.apache.ws.security.processor.EncryptedKeyProcessor.class
            );
            tmp.put(
                WSSecurityEngine.SIGNATURE,
                org.apache.ws.security.processor.SignatureProcessor.class
            );
            tmp.put(
                WSSecurityEngine.TIMESTAMP,
                org.apache.ws.security.processor.TimestampProcessor.class
            );
            tmp.put(
                WSSecurityEngine.USERNAME_TOKEN,
                org.apache.ws.security.processor.UsernameTokenProcessor.class
            );
            tmp.put(
                WSSecurityEngine.REFERENCE_LIST,
                org.apache.ws.security.processor.ReferenceListProcessor.class
            );
            tmp.put(
                WSSecurityEngine.SIGNATURE_CONFIRMATION,
                org.apache.ws.security.processor.SignatureConfirmationProcessor.class
            );
            tmp.put(
                WSSecurityEngine.DERIVED_KEY_TOKEN_05_02,
                org.apache.ws.security.processor.DerivedKeyTokenProcessor.class
            );
            tmp.put(
                WSSecurityEngine.DERIVED_KEY_TOKEN_05_12,
                tmp.get(WSSecurityEngine.DERIVED_KEY_TOKEN_05_02)
            );
            tmp.put(
                WSSecurityEngine.SECURITY_CONTEXT_TOKEN_05_02,
                org.apache.ws.security.processor.SecurityContextTokenProcessor.class
            );
            tmp.put(
                WSSecurityEngine.SECURITY_CONTEXT_TOKEN_05_12,
                tmp.get(WSSecurityEngine.SECURITY_CONTEXT_TOKEN_05_02)
            );
            tmp.put(
                WSSecurityEngine.BINARY_TOKEN,
                org.apache.ws.security.processor.BinarySecurityTokenProcessor.class
            );
            tmp.put(
                WSSecurityEngine.ENCRYPTED_DATA,
                org.apache.ws.security.processor.EncryptedDataProcessor.class
            );
        } catch (final Throwable t) {
            if (log.isDebugEnabled()) {
                log.debug(t.getMessage(), t);
            }
        }
        DEFAULT_PROCESSORS = java.util.Collections.unmodifiableMap(tmp);
    }

    protected boolean wsiBSPCompliant = false;

    /**
     * Set the timestamp precision mode. If set to <code>true</code> then use
     * timestamps with milliseconds, otherwise omit the milliseconds. As per XML
     * Date/Time specification the default is to include the milliseconds.
     */
    protected boolean precisionInMilliSeconds = true;

    protected boolean enableSignatureConfirmation = true;

    /**
     * If set to true then the timestamp handling will throw an exception if the
     * timestamp contains an expires element and the semantics are expired.
     * 
     * If set to false, no exception will be thrown, even if the semantics are
     * expired.
     */
    protected boolean timeStampStrict = true;
    
    /**
     * If this value is not null, then username token handling will throw an 
     * exception if the password type of the Username Token does not match this value
     */
    protected String requiredPasswordType = null;
    
    /**
     * The time in seconds between creation and expiry for a Timestamp. The default
     * is 300 seconds (5 minutes).
     */
    protected int timeStampTTL = 300;
    
    /**
     * This variable controls whether types other than PasswordDigest or PasswordText
     * are allowed when processing UsernameTokens. 
     * 
     * By default this is set to false so that the user doesn't have to explicitly
     * reject custom token types in the callback handler.
     */
    protected boolean handleCustomPasswordTypes = false;
    
    /**
     * This variable controls whether (wsse) namespace qualified password types are
     * accepted when processing UsernameTokens.
     * 
     * By default this is set to false.
     */
    protected boolean allowNamespaceQualifiedPasswordTypes = false;
    
    /**
     * The secret key length to be used for UT_SIGN.
     */
    protected int secretKeyLength = WSConstants.WSE_DERIVED_KEY_LEN;

    /**
     * Whether the password should be treated as a binary value.  This
     * is needed to properly handle password equivalence for UsernameToken
     * passwords.  Binary passwords are Base64 encoded so they can be
     * treated as strings in most places, but when the password digest
     * is calculated or a key is derived from the password, the password
     * will be Base64 decoded before being used. This is most useful for
     * hashed passwords as password equivalents.
     *
     * See https://issues.apache.org/jira/browse/WSS-239
     */
    protected boolean passwordsAreEncoded = false;
    
    /**
     * The default wsu:Id allocator is a simple "start at 1 and increment up"
     * thing that is very fast.
     */
    public static WsuIdAllocator DEFAULT_ID_ALLOCATOR = new WsuIdAllocator() {
        int i;
        private synchronized String next() {
            return Integer.toString(++i);
        }
        public String createId(String prefix, Object o) {
            if (prefix == null) {
                return next();
            }
            return prefix + next();
        }

        public String createSecureId(String prefix, Object o) {
            if (prefix == null) {
                return UUIDGenerator.getUUID();
            }
            return prefix + UUIDGenerator.getUUID();
        }
    };
    protected WsuIdAllocator idAllocator = DEFAULT_ID_ALLOCATOR;
    
    protected Map<String, String> jceProvider = new HashMap<String, String>();

    /**
     * The known actions. This map is of the form <Integer, Class<?>> or 
     * <Integer, Action>. 
     * The known actions are initialized from a set of defaults,
     * but the list may be modified via the setAction operations.
     */
    private final Map<Integer, Object> actionMap = 
        new HashMap<Integer, Object>(DEFAULT_ACTIONS);

    /**
     * The known processors. This map is of the form <QName, Class<?>> or
     * <QName, Processor>.
     * The known processors are initialized from a set of defaults,
     * but the list may be modified via the setProcessor operations.
     */
    private final Map<QName, Object> processorMap = 
        new HashMap<QName, Object>(DEFAULT_PROCESSORS);
    
    /**
     * a static boolean flag that determines whether default JCE providers
     * should be added at the time of construction.
     *
     * These providers, and the order in which they are added, can interfere
     * with some JVMs (such as IBMs).
     */
    private static boolean addJceProviders = true;
    
    /**
     * a boolean flag to record whether we have already been statically
     * initialized.  This flag prevents repeated and unnecessary calls
     * to static initialization code at construction time.
     */
    private static boolean staticallyInitialized = false;
    
    /**
     * Set the value of the internal addJceProviders flag.  This flag
     * turns on (or off) automatic registration of known JCE providers
     * that provide necessary cryptographic algorithms for use with WSS4J.
     * By default, this flag is true, for backwards compatibility.  You may
     * wish (or need) to initialize the JCE manually, e.g., in some JVMs.
     */
    public static void setAddJceProviders(boolean value) {
        addJceProviders = value;
    }
    
    private synchronized void
    staticInit() {
        if (!staticallyInitialized) {
            org.apache.xml.security.Init.init();
            if (addJceProviders) {
                addJceProvider("BC", "org.bouncycastle.jce.provider.BouncyCastleProvider");
                appendJceProvider("XMLDSig", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
                appendJceProvider(
                    "STRTransform", "org.apache.ws.security.transform.STRTransformProvider"
                );
            }
            
            staticallyInitialized = true;
        }
    }
    
    protected WSSConfig() {
        staticInit();
    }
    
    /**
     * @return a new WSSConfig instance configured with the default values
     */
    public static WSSConfig getNewInstance() {
        return new WSSConfig();
    }

    /**
     * Checks if we are in WS-I Basic Security Profile compliance mode
     * 
     * @return whether we are in WS-I Basic Security Profile compliance mode
     */
    public boolean isWsiBSPCompliant() {
        return wsiBSPCompliant;
    }

    /**
     * Set the WS-I Basic Security Profile compliance mode. The default is false
     * (dues to .Net interop problems).
     * 
     * @param wsiBSPCompliant
     */
    public void setWsiBSPCompliant(boolean wsiBSPCompliant) {
        this.wsiBSPCompliant = wsiBSPCompliant;
    }

    /**
     * Checks if we need to use milliseconds in timestamps
     * 
     * @return whether to use precision in milliseconds for timestamps
     */
    public boolean isPrecisionInMilliSeconds() {
        return precisionInMilliSeconds;
    }

    /**
     * Set the precision in milliseconds for timestamps
     * 
     * @param precisionInMilliSeconds whether to use precision in milliseconds for timestamps
     */
    public void setPrecisionInMilliSeconds(boolean precisionInMilliSeconds) {
        this.precisionInMilliSeconds = precisionInMilliSeconds;
    }

    /**
     * @return Returns the enableSignatureConfirmation.
     */
    public boolean isEnableSignatureConfirmation() {
        return enableSignatureConfirmation;
    }

    /**
     * @param enableSignatureConfirmation
     *            The enableSignatureConfirmation to set.
     */
    public void setEnableSignatureConfirmation(boolean enableSignatureConfirmation) {
        this.enableSignatureConfirmation = enableSignatureConfirmation;
    }
    
    /**
     * @param handleCustomTypes 
     * whether to handle custom UsernameToken password types or not
     */
    public void setHandleCustomPasswordTypes(boolean handleCustomTypes) {
        this.handleCustomPasswordTypes = handleCustomTypes;
    }
    
    /**
     * @return whether custom UsernameToken password types are allowed or not
     */
    public boolean getHandleCustomPasswordTypes() {
        return handleCustomPasswordTypes;
    }
    
    /**
     * @param allowNamespaceQualifiedTypes
     * whether (wsse) namespace qualified password types are accepted or not
     */
    public void setAllowNamespaceQualifiedPasswordTypes(boolean allowNamespaceQualifiedTypes) {
        allowNamespaceQualifiedPasswordTypes = allowNamespaceQualifiedTypes;
    }
    
    /**
     * @return whether (wsse) namespace qualified password types are accepted or not
     */
    public boolean getAllowNamespaceQualifiedPasswordTypes() {
        return allowNamespaceQualifiedPasswordTypes;
    }
    
    /**
     * @return Returns if we shall throw an exception on expired request
     *         semantic
     */
    public boolean isTimeStampStrict() {
        return timeStampStrict;
    }

    /**
     * @param timeStampStrict
     *            If true throw an exception on expired request semantic
     */
    public void setTimeStampStrict(boolean timeStampStrict) {
        this.timeStampStrict = timeStampStrict;
    }
    
    /**
     * @return the required password type when processing a UsernameToken
     */
    public String getRequiredPasswordType() {
        return requiredPasswordType;
    }

    /**
     * @param requiredPasswordType The required password type when processing
     * a Username Token.
     */
    public void setRequiredPasswordType(String requiredPasswordType) {
        this.requiredPasswordType = requiredPasswordType;
    }
    
    /**
     * @return Returns the TTL of a Timestamp in seconds
     */
    public int getTimeStampTTL() {
        return timeStampTTL;
    }

    /**
     * @param timeStampTTL
     *            The new value for timeStampTTL
     */
    public void setTimeStampTTL(int timeStampTTL) {
        this.timeStampTTL = timeStampTTL;
    }
    
    /**
     * Set the secret key length to be used for UT_SIGN.
     */
    public void setSecretKeyLength(int length) {
        secretKeyLength = length;
    }
    
    /**
     * Get the secret key length to be used for UT_SIGN.
     */
    public int getSecretKeyLength() {
        return secretKeyLength;
    }
    
    /**
     * @param passwordsAreEncoded
     * whether passwords are encoded
     */
    public void setPasswordsAreEncoded(boolean passwordsAreEncoded) {
        this.passwordsAreEncoded = passwordsAreEncoded;
    }
    
    /**
     * @return whether passwords are encoded
     */
    public boolean getPasswordsAreEncoded() {
        return passwordsAreEncoded;
    }
    
    /**
     * @return Returns the WsuIdAllocator used to generate wsu:Id attributes
     */
    public WsuIdAllocator getIdAllocator() {
        return idAllocator;
    }

    public void setIdAllocator(WsuIdAllocator idAllocator) {
        this.idAllocator = idAllocator;
    }
    
    /**
     * Associate an action instance with a specific action code.
     *
     * This operation allows applications to supply their own
     * actions for well-known operations.
     * 
     * Please note that the Action object does NOT get class-loaded per invocation, and so
     * it is up to the implementing class to ensure that it is thread-safe.
     */
    public Class<?> setAction(int code, Action action) {
        Object result = actionMap.put(new Integer(code), action);
        if (result instanceof Class<?>) {
            return (Class<?>)result;
        } else if (result instanceof Action) {
            return result.getClass();
        }
        return null;
    }
    
    /**
     * Associate an action instance with a specific action code.
     *
     * This operation allows applications to supply their own
     * actions for well-known operations.
     */
    public Class<?> setAction(int code, Class<?> clazz) {
        Object result = actionMap.put(new Integer(code), clazz);
        if (result instanceof Class<?>) {
            return (Class<?>)result;
        } else if (result instanceof Action) {
            return result.getClass();
        }
        return null;
    }

    /**
     * Lookup action
     * 
     * @param action
     * @return An action class to create a security token
     * @throws WSSecurityException
     */
    public Action getAction(int action) throws WSSecurityException {
        final Object actionObject = actionMap.get(new Integer(action));
        
        if (actionObject instanceof Class<?>) {
            try {
                return (Action)((Class<?>)actionObject).newInstance();
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug(t.getMessage(), t);
                }
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "unableToLoadClass", new Object[] { ((Class<?>)actionObject).getName() }, t);
            }
        } else if (actionObject instanceof Action) {
            return (Action)actionObject;
        }
        return null;
    }
    
    /**
     * Associate a SOAP processor name with a specified SOAP Security header
     * element QName.  Processors registered under this QName will be
     * called when processing header elements with the specified type.
     * 
     * Please note that the Processor object does NOT get class-loaded per invocation, and so
     * it is up to the implementing class to ensure that it is thread-safe.
     */
    public Class<?> setProcessor(QName el, Processor processor) {
        Object result = processorMap.put(el, processor);
        if (result instanceof Class<?>) {
            return (Class<?>)result;
        } else if (result instanceof Processor) {
            return result.getClass();
        }
        return null;
    }
    
    /**
     * Associate a SOAP processor name with a specified SOAP Security header
     * element QName.  Processors registered under this QName will be
     * called when processing header elements with the specified type.
     */
    public Class<?> setProcessor(QName el, Class<?> clazz) {
        Object result = processorMap.put(el, clazz);
        if (result instanceof Class<?>) {
            return (Class<?>)result;
        } else if (result instanceof Processor) {
            return result.getClass();
        }
        return null;
    }
    
    /**
     * @return      the SOAP processor associated with the specified
     *              QName.  The QName is intended to refer to an element
     *              in a SOAP security header.  This operation returns
     *              null if there is no processor associated with the 
     *              specified QName.
     */
    public Processor getProcessor(QName el) throws WSSecurityException {
        final Object processorObject = processorMap.get(el);
        
        if (processorObject instanceof Class<?>) {
            try {
                return (Processor)((Class<?>)processorObject).newInstance();
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug(t.getMessage(), t);
                }
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "unableToLoadClass", new Object[] { ((Class<?>)processorObject).getName() }, t);
            }
        } else if (processorObject instanceof Processor) {
            return (Processor)processorObject;
        }
        return null;
    }

    
    /**
     * Add a new JCE security provider to use for WSS4J, of the specified name and class. Return
     * either the name of the previously loaded provider, the name of the new loaded provider, or
     * null if there's an exception in loading the provider. Add the provider either after the SUN
     * provider (see WSS-99), or the IBMJCE provider. Otherwise fall back to the old behaviour of
     * inserting the provider in position 2.
     * 
     * @param name
     *            The name string of the provider (this may not be the real name of the provider)
     * @param className
     *            Name of the class the implements the provider. This class must
     *            be a subclass of <code>java.security.Provider</code>
     * 
     * @return Returns the actual name of the provider that was loaded
     */
    public String addJceProvider(String name, String className) {
        if (jceProvider.get(name) == null) {
            String newName = null;
            try {
                if (Security.getProvider(name) == null) {
                    Class<?> c = Loader.loadClass(className, false);
                    Provider[] provs = Security.getProviders();
                    Provider newProvider = (Provider)c.newInstance();
                    //
                    // Install the provider after the SUN provider (see WSS-99)
                    // Otherwise fall back to the old behaviour of inserting
                    // the provider in position 2. For AIX, install it after
                    // the IBMJCE provider.
                    //
                    int ret = 0;
                    for (int i = 0; i < provs.length; i++) {
                        if ("SUN".equals(provs[i].getName())
                            || "IBMJCE".equals(provs[i].getName())) {
                            ret = Security.insertProviderAt(newProvider, i + 2);
                            break;
                        }
                    }
                    if (ret == 0) {
                        ret = Security.insertProviderAt(newProvider, 2);
                    }
                    if (log.isDebugEnabled()) {
                        log.debug(
                            "The provider " + newProvider.getName() + " was added at position: " + ret
                        );
                    }
                    newName = newProvider.getName();
                } else {
                    newName = name;
                }
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug("The provider " + name + " could not be added: " + t.getMessage(), t);
                }
                newName = null;
            }
            if (newName != null) {
                jceProvider.put(newName, className);
            }
            return newName;
        }
        return name;
    }
    
    
    /**
     * Add a new JCE security provider to use for WSS4J, of the specified name and class. Return
     * either the name of the previously loaded provider, the name of the new loaded provider, or
     * null if there's an exception in loading the provider. Append the provider to the provider
     * list.
     * 
     * @param name
     *            The name string of the provider (this may not be the real name of the provider)
     * @param className
     *            Name of the class the implements the provider. This class must
     *            be a subclass of <code>java.security.Provider</code>
     * 
     * @return Returns the actual name of the provider that was loaded
     */
    public String appendJceProvider(String name, String className) {
        if (jceProvider.get(name) == null) {
            String newName = null;
            try {
                if (Security.getProvider(name) == null) {
                    Class<?> c = Loader.loadClass(className, false);
                    Provider newProvider = (Provider)c.newInstance();
                    int ret = Security.addProvider(newProvider);
                    if (log.isDebugEnabled()) {
                        log.debug(
                            "The provider " + newProvider.getName() + " was added at position: " + ret
                        );
                    }
                    newName = newProvider.getName();
                } else {
                    newName = name;
                }
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug("The provider " + name + " could not be added: " + t.getMessage(), t);
                }
                newName = null;
            }
            if (newName != null) {
                jceProvider.put(newName, className);
            }
            return newName;
        }
        return name;
    }
    
}
