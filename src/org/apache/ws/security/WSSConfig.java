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
    private static Log log = LogFactory.getLog(WSSConfig.class.getName());

    protected static WSSConfig defaultConfig = getNewInstance();

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

    protected WSSConfig() {
        org.apache.xml.security.Init.init();
        /*
         * The last provider added has precedence, that is if JuiCE can be add
         * then WSS4J uses this provider.
         */
        addJceProvider("BC",
                "org.bouncycastle.jce.provider.BouncyCastleProvider");
        addJceProvider("JuiCE",
                "org.apache.security.juice.provider.JuiCEProviderOpenSSL");
        Transform.init();
        try {
            Transform.register(STRTransform.implementedTransformURI,
                    "org.apache.ws.security.transform.STRTransform");
        } catch (Exception ex) {
        }
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
     * Lookup action
     * 
     * @param action
     * @return An action class to create a security token
     * @throws WSSecurityException
     */
    public Action getAction(int action) throws WSSecurityException {
        String name = null;
        switch (action) {
        case WSConstants.UT:
            name = "org.apache.ws.security.action.UsernameTokenAction";
            break;

        case WSConstants.ENCR:
            name = "org.apache.ws.security.action.EncryptionAction";
            break;

        case WSConstants.SIGN:
            name = "org.apache.ws.security.action.SignatureAction";
            break;

        case WSConstants.ST_SIGNED:
            name = "org.apache.ws.security.action.SAMLTokenSignedAction";
            break;

        case WSConstants.ST_UNSIGNED:
            name = "org.apache.ws.security.action.SAMLTokenUnsignedAction";
            break;

        case WSConstants.TS:
            name = "org.apache.ws.security.action.TimestampAction";
            break;

        case WSConstants.UT_SIGN:
            name = "org.apache.ws.security.action.UsernameTokenSignedAction";
            break;
        case WSConstants.SC:
            name = "org.apache.ws.security.action.SignatureConfirmationAction";
            break;
        }
        if (name == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "unknownAction", new Object[] { new Integer(action) });
        }
        try {
            return (Action) Loader.loadClass(name).newInstance();
        } catch (Throwable t) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "unableToLoadClass", new Object[] { name });
        }
    }

    public Processor getProcessor(QName el) throws WSSecurityException {
        String name = null;
        if (el.equals(WSSecurityEngine.SAML_TOKEN)) {
            name = "org.apache.ws.security.processor.SAMLTokenProcessor";
        } else if (el.equals(WSSecurityEngine.ENCRYPTED_KEY)) {
            name = "org.apache.ws.security.processor.EncryptedKeyProcessor";
        } else if (el.equals(WSSecurityEngine.SIGNATURE)) {
            name = "org.apache.ws.security.processor.SignatureProcessor";
        } else if (el.equals(WSSecurityEngine.timeStamp)) {
            name = "org.apache.ws.security.processor.TimestampProcessor";
        } else if (el.equals(WSSecurityEngine.usernameToken)) {
            name = "org.apache.ws.security.processor.UsernameTokenProcessor";
        } else if (el.equals(WSSecurityEngine.REFERENCE_LIST)) {
            name = "org.apache.ws.security.processor.ReferenceListProcessor";
        } else if (el.equals(WSSecurityEngine.signatureConfirmation)) {
            name = "org.apache.ws.security.processor.SignatureConfirmationProcessor";
        } else if (el.equals(WSSecurityEngine.DERIVED_KEY_TOKEN_05_02) ||
                el.equals(WSSecurityEngine.DERIVED_KEY_TOKEN_05_12)) {
            name = "org.apache.ws.security.processor.DerivedKeyTokenProcessor";
        } else if(el.equals(WSSecurityEngine.SECURITY_CONTEXT_TOKEN_05_02) ||
                el.equals(WSSecurityEngine.SECURITY_CONTEXT_TOKEN_05_12)) {
            name = "org.apache.ws.security.processor.SecurityContextTokenProcessor";
        } else if(el.equals(WSSecurityEngine.binaryToken)) {
            name = "org.apache.ws.security.processor.BinarySecurityTokenProcessor";
        } else if(el.equals(WSSecurityEngine.ENCRYPTED_DATA)) {
            name = "org.apache.ws.security.processor.EncryptedDataProcessor";
        }

        if (name != null) {
            try {
                return (Processor) Loader.loadClass(name).newInstance();
            } catch (Throwable t) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "unableToLoadClass", new Object[] { name });
            }
        }
        return null;
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
