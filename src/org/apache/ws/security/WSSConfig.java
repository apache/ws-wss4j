/*
 * Copyright  2003-2004 The Apache Software Foundation.
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
 */
public class WSSConfig {
    private static Log log = LogFactory.getLog(WSSConfig.class.getName());
    protected static WSSConfig defaultConfig = getNewInstance();
    protected String wsse_ns = WSConstants.WSSE_NS_OASIS_1_0;
    protected String wsu_ns = WSConstants.WSU_NS_OASIS_1_0;
    protected boolean qualifyBSTAttributes = false;
    protected boolean prefixBSTValues = false;
    protected boolean targetIdQualified = true;
    protected boolean wsiBSPCompliant = false;
    protected boolean processNonCompliantMessages = true;
    public static final int TIMESTAMP_IN_SECURITY_ELEMENT = 1;
    public static final int TIMESTAMP_IN_HEADER_ELEMENT = 2;
    protected int timestampLocation = TIMESTAMP_IN_SECURITY_ELEMENT;

    /**
     * Set the timestamp precision mode.
     * If set to <code>true</code> then use timestamps with milliseconds,
     * otherwise omit the millisconds. As per XML Date/Time specification
     * the defualt is to include the milliseconds.
     */
    protected boolean precisionInMilliSeconds = true;

    protected WSSConfig() {
        org.apache.xml.security.Init.init();
        try {
            Class c = Loader.loadClass("org.bouncycastle.jce.provider.BouncyCastleProvider");
            String Id = "BC";
            if (java.security.Security.getProvider(Id) == null) {
                log.debug("The provider " + Id
                        + " had to be added to the java.security.Security");
                java.security.Security.addProvider((java.security.Provider)c.newInstance());
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
     * default value is {@link WSConstants.WSSE_NS_OASIS_1_0}
     * <p/>
     * The WS-Security namespace
     */
    public String getWsseNS() {
        return wsse_ns;
    }

    /**
     * Valid values:
     * <ul>
     * <li> {@link WSConstants#WSSE_NS_OASIS_2002_07} </li>
     * <li> {@link WSConstants#WSSE_NS_OASIS_2002_12} </li>
     * <li> {@link WSConstants#WSSE_NS_OASIS_2003_06} </li>
     * <li> {@link WSConstants#WSSE_NS_OASIS_1_0} OASIS WS-Security v1.0 (March 2004). This is the default and recommended setting</li>
     * </ul>
     */
    public void setWsseNS(String wsseNamespace) {
        wsse_ns = wsseNamespace;
    }

    /**
     * default value is {@link WSConstants.WSU_NS_OASIS_1_0}
     * <p/>
     * The WS-Security utility namespace
     */
    public String getWsuNS() {
        return wsu_ns;
    }

    /**
     * Valid values:
     * <ul>
     * <li> {@link WSConstants#WSU_NS_OASIS_2002_07} </li>
     * <li> {@link WSConstants#WSU_NS_OASIS_2002_12} </li>
     * <li> {@link WSConstants#WSU_NS_OASIS_2003_06} </li>
     * <li> {@link WSConstants#WSU_NS_OASIS_1_0} OASIS WS-Security v1.0 (March 2004). This is the default and recommended setting</li>
     * </ul>
     */
    public void setWsuNS(String wsuNamespace) {
        wsu_ns = wsuNamespace;
    }

    /**
     * default value is false.
     * <p/>
     * returns true if the BinarySecurityToken EncodingType and ValueType
     * attributes should be namespace qualified.
     */
    public boolean isBSTAttributesQualified() {
        return qualifyBSTAttributes;
    }

    /**
     * specify if the BinarySecurityToken EncodingType and ValueType
     * attributes should be namespace qualified. The default value is false.
     */
    public void setBSTAttributesQualified(boolean qualifyBSTAttributes) {
        this.qualifyBSTAttributes = qualifyBSTAttributes;
    }

    /**
     * default value is false.
     * <p/>
     * returns true if the BinarySecurityToken EncodingType and ValueType
     * attribute values should be prefixed with "wsse" or otherwise qualified
     * with the wsse namespace (false).
     */
    public boolean isBSTValuesPrefixed() {
        return prefixBSTValues;
    }

    /**
     * sets and option whether the BinarySecurityToken EncodingType and ValueType
     * attribute values should be prefixed with "wsse" or otherwise qualified
     * with the wsse namespace (false).
     */
    public void setBSTValuesPrefixed(boolean prefixBSTAttributeValues) {
        prefixBSTValues = prefixBSTAttributeValues;
    }

    /**
     * default value is true.
     * <p/>
     * returns true if the Id attribute placed in the signature target element is
     * qualified with the wsu namespace.
     */
    public boolean isTargetIdQualified() {
        return targetIdQualified;
    }

    /**
     * Sets an option whether the Id attribute placed in the signature target should be
     * qualified with the wsu namespace.
     */
    public void setTargetIdQualified(boolean qualifyTargetIdAttribute) {
        targetIdQualified = qualifyTargetIdAttribute;
    }

    /**
     * default value is TIMESTAMP_IN_SECURITY_ELEMENT (following OASIS 2003 and 2004 specs).
     * <p/>
     * returns TIMESTAMP_IN_SECURITY_ELEMENT if the wsu:Timestamp element is placed inside
     * the wsse:Secutriy element. TIMESTAMP_IN_HEADER_ELEMENT if it is placed under the Header directly, outside
     * the wsse:Secutriy element.
     */
    public int getTimestampLocation() {
        return timestampLocation;
    }

    /**
     * Sets an option whether the Iwsu:Timestamp element is placed inside
     * the wsse:Secutriy element. set it to false foe placement in the Header,
     * outside the wsse:Secutriy element.
     */
    public void setTimestampLocation(int timestampElementLocation) {
        timestampLocation = timestampElementLocation;
    }

    /**
     * default value is true.
     * <p/>
     * returns true if WSS4J attempts to process non-compliant WS-Security
     * messages, such as WS-Security headers with older OASIS spec namespaces.
     */
    public boolean getProcessNonCompliantMessages() {
        return processNonCompliantMessages;
    }

    /**
     * Sets an option whether WSS4J should attempt to process non-compliant
     * WS-Security messages, such as WS-Security headers with older OASIS spec
     * namespaces.
     */
    public void setProcessNonCompliantMessages(boolean attemptProcess) {
        processNonCompliantMessages = attemptProcess;
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
}
