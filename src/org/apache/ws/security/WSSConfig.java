/*
 * Copyright  2003-2005 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.apache.ws.security;

import java.util.HashMap;

import javax.xml.namespace.QName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.action.Action;
import org.apache.ws.security.processor.Processor;
import org.apache.ws.security.transform.STRTransform;
import org.apache.ws.security.util.Loader;
import org.apache.xml.security.transforms.Transform;

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

    /**
     * The default collection of actions supported by the toolkit.
     */
    private static final java.util.Map DEFAULT_ACTIONS;
    static {
        final java.util.Map tmp = new java.util.HashMap();
        try {
            tmp.put(
                new Integer(WSConstants.UT),
                (Action) Loader.loadClass(
                    org.apache.ws.security.action.UsernameTokenAction.class.getName()
                ).newInstance()
            );
            tmp.put(
                new Integer(WSConstants.ENCR),
                (Action) Loader.loadClass(
                    org.apache.ws.security.action.EncryptionAction.class.getName()
                ).newInstance()
            );
            tmp.put(
                new Integer(WSConstants.SIGN),
                (Action) Loader.loadClass(
                    org.apache.ws.security.action.SignatureAction.class.getName()
                ).newInstance()
            );
            tmp.put(
                new Integer(WSConstants.ST_SIGNED),
                (Action) Loader.loadClass(
                    org.apache.ws.security.action.SAMLTokenSignedAction.class.getName()
                ).newInstance()
            );
            tmp.put(
                new Integer(WSConstants.ST_UNSIGNED),
                (Action) Loader.loadClass(
                    org.apache.ws.security.action.SAMLTokenUnsignedAction.class.getName()
                ).newInstance()
            );
            tmp.put(
                new Integer(WSConstants.TS),
                (Action) Loader.loadClass(
                    org.apache.ws.security.action.TimestampAction.class.getName()
                ).newInstance()
            );
            tmp.put(
                new Integer(WSConstants.UT_SIGN),
                (Action) Loader.loadClass(
                    org.apache.ws.security.action.UsernameTokenSignedAction.class.getName()
                ).newInstance()
            );
            tmp.put(
                new Integer(WSConstants.SC),
                (Action) Loader.loadClass(
                    org.apache.ws.security.action.SignatureConfirmationAction.class.getName()
                ).newInstance()
            );
        } catch (final Throwable t) {
            t.printStackTrace();
        }
        DEFAULT_ACTIONS = java.util.Collections.unmodifiableMap(tmp);
    }

    /**
     * The default collection of processors supported by the toolkit
     */
    private static final java.util.Map DEFAULT_PROCESSORS;
    static {
        final java.util.Map tmp = new java.util.HashMap();
        try {
            tmp.put(
                WSSecurityEngine.SAML_TOKEN,
                (Processor) Loader.loadClass(
                    org.apache.ws.security.processor.SAMLTokenProcessor.class.getName()
                ).newInstance()
            );
            tmp.put(
                WSSecurityEngine.ENCRYPTED_KEY,
                (Processor) Loader.loadClass(
                    org.apache.ws.security.processor.EncryptedKeyProcessor.class.getName()
                ).newInstance()
            );
            tmp.put(
                WSSecurityEngine.SIGNATURE,
                (Processor) Loader.loadClass(
                    org.apache.ws.security.processor.SignatureProcessor.class.getName()
                ).newInstance()
            );
            tmp.put(
                WSSecurityEngine.timeStamp,
                (Processor) Loader.loadClass(
                    org.apache.ws.security.processor.TimestampProcessor.class.getName()
                ).newInstance()
            );
            tmp.put(
                WSSecurityEngine.usernameToken,
                (Processor) Loader.loadClass(
                    org.apache.ws.security.processor.UsernameTokenProcessor.class.getName()
                ).newInstance()
            );
            tmp.put(
                WSSecurityEngine.REFERENCE_LIST,
                (Processor) Loader.loadClass(
                    org.apache.ws.security.processor.ReferenceListProcessor.class.getName()
                ).newInstance()
            );
            tmp.put(
                WSSecurityEngine.signatureConfirmation,
                (Processor) Loader.loadClass(
                    org.apache.ws.security.processor.SignatureConfirmationProcessor.class.getName()
                ).newInstance()
            );
            tmp.put(
                WSSecurityEngine.DERIVED_KEY_TOKEN_05_02,
                (Processor) Loader.loadClass(
                    org.apache.ws.security.processor.DerivedKeyTokenProcessor.class.getName()
                ).newInstance()
            );
            tmp.put(
                WSSecurityEngine.DERIVED_KEY_TOKEN_05_12,
                tmp.get(WSSecurityEngine.DERIVED_KEY_TOKEN_05_02)
            );
            tmp.put(
                WSSecurityEngine.SECURITY_CONTEXT_TOKEN_05_02,
                (Processor) Loader.loadClass(
                    org.apache.ws.security.processor.SecurityContextTokenProcessor.class.getName()
                ).newInstance()
            );
            tmp.put(
                WSSecurityEngine.SECURITY_CONTEXT_TOKEN_05_12,
                tmp.get(WSSecurityEngine.SECURITY_CONTEXT_TOKEN_05_02)
            );
            tmp.put(
                WSSecurityEngine.binaryToken,
                (Processor) Loader.loadClass(
                    org.apache.ws.security.processor.BinarySecurityTokenProcessor.class.getName()
                ).newInstance()
            );
            tmp.put(
                WSSecurityEngine.ENCRYPTED_DATA,
                (Processor) Loader.loadClass(
                    org.apache.ws.security.processor.EncryptedDataProcessor.class.getName()
                ).newInstance()
            );
        } catch (final Throwable t) {
            t.printStackTrace();
        }
        DEFAULT_PROCESSORS = java.util.Collections.unmodifiableMap(tmp);
    }

    private static Log log = LogFactory.getLog(WSSConfig.class.getName());

    protected static WSSConfig defaultConfig = null;

    protected boolean wsiBSPCompliant = false;

    /**
     * Set the timestamp precision mode. If set to <code>true</code> then use
     * timestamps with milliseconds, otherwise omit the millisconds. As per XML
     * Date/Time specification the default is to include the milliseconds.
     */
    protected boolean precisionInMilliSeconds = true;

    protected boolean enableSignatureConfirmation = true;

    /**
     * If set to true then the timestamp handling will throw an expcetion if the
     * timestamp contains an expires element and the semantics are expired.
     * 
     * If set to false, not expetion will be thrown, even if the semantics are
     * expired.
     */
    protected boolean timeStampStrict = true;

    protected HashMap jceProvider = new HashMap(10);

    /**
     * The known actions.  These are initialized from a set of defaults,
     * but the list may be modified via the setAction operation.
     */
    private final java.util.Map actionMap = new java.util.HashMap(DEFAULT_ACTIONS);

    /**
     * The known processors.  These are initialized from a set of defaults,
     * but the list may be modified via the setProcessor operation.
     */
    private final java.util.Map processorMap = new java.util.HashMap(DEFAULT_PROCESSORS);
    
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
     * initialized.  This flag prevents repeated and unecessary calls
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
            /*
             * The last provider added has precedence, that is if JuiCE can be add
             * then WSS4J uses this provider.
             */
            addJceProvider("BC",
                    "org.bouncycastle.jce.provider.BouncyCastleProvider");
            addJceProvider("JuiCE",
                    "org.apache.security.juice.provider.JuiCEProviderOpenSSL");
            }
            Transform.init();
            try {
                Transform.register(STRTransform.implementedTransformURI,
                        "org.apache.ws.security.transform.STRTransform");
            } catch (Exception ex) {
                // TODO log error
            }
            staticallyInitialized = true;
        }
    }
    
    protected WSSConfig() {
        staticInit();
    }
    
    /**
     * @return a new WSSConfig instance configured with the default values
     *         (values identical to
     *         {@link #getDefaultWSConfig getDefaultWSConfig()})
     */
    public static WSSConfig getNewInstance() {
        WSSConfig config = new WSSConfig();
        return config;
    }

    /**
     * returns a static WSConfig instance that is configured with the latest
     * OASIS WS-Seurity settings.
     */
    public static WSSConfig getDefaultWSConfig() {
        if (defaultConfig == null) {
            defaultConfig = getNewInstance();
        }
        return defaultConfig;
    }

    /**
     * Checks if we are in WS-I Basic Security Profile compliance mode
     * 
     * @return TODO
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
     * @return TODO
     */
    public boolean isPrecisionInMilliSeconds() {
        return precisionInMilliSeconds;
    }

    /**
     * Set the precision in milliseconds
     * 
     * @param precisionInMilliSeconds
     *            TODO
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
    public void setEnableSignatureConfirmation(
            boolean enableSignatureConfirmation) {
        this.enableSignatureConfirmation = enableSignatureConfirmation;
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
     * Associate an action with a specific action code.
     *
     * This operation allows applications to supply their own
     * actions for well-known operations.
     */
    public Action setAction(int code, Action action) {
        return (Action) actionMap.put(new Integer(code), action);
    }

    /**
     * Lookup action
     * 
     * @param action
     * @return An action class to create a security token
     * @throws WSSecurityException
     */
    public Action getAction(int action) throws WSSecurityException {
        Integer key = new Integer(action);
        Action ret = (Action) actionMap.get(key);
        if (ret == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "unknownAction", new Object[] { key });
        }
        return ret;
    }
    
    /**
     * Associate a SOAP processor with a specified SOAP Security header
     * element QName.  Processors registered under this QName will be
     * called when processing header elements with the specified type.
     */
    public Processor setProcessor(QName el, Processor p) {
        return (Processor) processorMap.put(el, p);
    }

    /**
     * @return      the SOAP processor associated with the specified
     *              QName.  The QName is intended to refer to an element
     *              in a SOAP security header.
     */
    public Processor getProcessor(QName el) throws WSSecurityException {
        Processor p = (Processor) processorMap.get(el);
        return p;
    }

    private boolean loadProvider(String id, String className) {
        try {
            Class c = Loader.loadClass(className);
            if (java.security.Security.getProvider(id) == null) {
                if (log.isDebugEnabled()) {
                    log.debug("The provider " + id
                            + " had to be added to the java.security.Security");
                }
                int ret =java.security.Security.insertProviderAt(
                        (java.security.Provider) c.newInstance(), 2);
                if (log.isDebugEnabled()) {
                    log.debug("The provider " + id + " was added at: "
                            + ret);
                }                
            }
            return true;
        } catch (Throwable t) {
            if (log.isDebugEnabled()) {
                log.debug("The provider " + id + " could not be added: "
                        + t.getMessage());
            }
            return false;
        }

    }

    /**
     * Add a new JCE security provider to use for WSS4J.
     * 
     * If the provider is not already known the method loads a security provider
     * class and adds the provider to the java security service.
     * 
     * 
     * @param id
     *            The id string of the provider
     * @param className
     *            Name of the class the implements the provider. This class must
     *            be a subclass of <code>java.security.Provider</code>
     * 
     * @return Returns <code>true</code> if the provider was successfully
     *         added, <code>false</code> otherwise.
     */
    public boolean addJceProvider(String id, String className) {
        if (jceProvider.get(id) == null && loadProvider(id, className)) {
            jceProvider.put(id, className);
            return true;
        }
        return false;
    }
}
