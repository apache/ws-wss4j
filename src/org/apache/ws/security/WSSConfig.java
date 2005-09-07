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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.transform.STRTransform;
import org.apache.ws.security.util.Loader;
import org.apache.xml.security.transforms.Transform;

/**
 * WSSConfig
 * <p/>
 * Carries configuration data so the WSS4J spec compliance can be modified in
 * runtime. Configure an instance of this object only if you need WSS4J to
 * emulate certain industry clients or previous OASIS specifications for
 * WS-Security interoperability testing purposes.
 * <p/>
 * The default settings follow the latest OASIS and changing anything might
 * violate the OASIS specs.
 * <p/>
 * <b>WARNING: changing the default settings will break the compliance with the
 * latest specs.  Do this only if you know what you are doing.</b>
 * <p/>
 *
 * @author Rami Jaamour (rjaamour@parasoft.com)
 * @author Werner Dittmann (Werner.Dittmann@t-online.de)
 */
public class WSSConfig {
    private static Log log = LogFactory.getLog(WSSConfig.class.getName());
    protected static WSSConfig defaultConfig = getNewInstance();
    protected boolean wsiBSPCompliant = false;
    /**
     * Set the timestamp precision mode.
     * If set to <code>true</code> then use timestamps with milliseconds,
     * otherwise omit the millisconds. As per XML Date/Time specification
     * the default is to include the milliseconds.
     */
    protected boolean precisionInMilliSeconds = true;
    
    protected boolean enableSignatureConfirmation = true;

    protected WSSConfig() {
        org.apache.xml.security.Init.init();
        try {
            Class c = Loader
                    .loadClass("org.bouncycastle.jce.provider.BouncyCastleProvider");
            String Id = "BC";
            if (java.security.Security.getProvider(Id) == null) {
                if (log.isDebugEnabled()) {
                    log.debug("The provider " + Id
                            + " had to be added to the java.security.Security");
                }
                java.security.Security.addProvider((java.security.Provider) c
                        .newInstance());
            }
        } catch (Throwable t) {
        }
        Transform.init();
        try {
            Transform.register(STRTransform.implementedTransformURI,
                    "org.apache.ws.security.transform.STRTransform");
        } catch (Exception ex) {
        }
    }

    /**
     * @return a new WSSConfig instance configured with the default values
     *         (values identical to {@link #getDefaultWSConfig getDefaultWSConfig()})
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
     * @return
     */
    public boolean isWsiBSPCompliant() {
        return wsiBSPCompliant;
    }

    /**
     * Set the WS-I Basic Security Profile compliance mode. The default is
     * false (dues to .Net interop problems).
     *
     * @param wsiBSPCompliant
     */
    public void setWsiBSPCompliant(boolean wsiBSPCompliant) {
        this.wsiBSPCompliant = wsiBSPCompliant;
    }

    /**
     * Checks if we need to use milliseconds in timestamps
     *
     * @return
     */
    public boolean isPrecisionInMilliSeconds() {
        return precisionInMilliSeconds;
    }

    /**
     * Set the precision in milliseconds
     *
     * @param wsiBSPCompliant
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
     * @param enableSignatureConfirmation The enableSignatureConfirmation to set.
     */
    public void setEnableSignatureConfirmation(boolean enableSignatureConfirmation) {
        this.enableSignatureConfirmation = enableSignatureConfirmation;
    }
}
