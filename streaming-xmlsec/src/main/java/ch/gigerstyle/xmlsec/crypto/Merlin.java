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
package ch.gigerstyle.xmlsec.crypto;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;

/**
 * class lent from apache wss4j
 */

/**
 * Created by IntelliJ IDEA.
 * User: dims
 * Date: Sep 15, 2005
 * Time: 9:50:40 AM
 * To change this template use File | Settings | File Templates.
 */
public class Merlin extends CryptoBase {

    private static final Log log = LogFactory.getLog(Merlin.class.getName());
    private static final boolean doDebug = log.isDebugEnabled();

    private String defaultX509Alias;

    /**
     * This allows providing a custom class loader to load the resources, etc
     *
     * @throws java.io.IOException
     */
    public Merlin() throws IOException {

        /**
         * Load cacerts
         */

        //todo:
        /*
        String loadCacerts =
                properties.getProperty(
                        "org.apache.ws.security.crypto.merlin.load.cacerts",
                        "true"
                );
        if (Boolean.valueOf(loadCacerts).booleanValue()) {
            String cacertsPath = System.getProperty("java.home") + "/lib/security/cacerts";
            InputStream cacertsIs = new FileInputStream(cacertsPath);
            try {
                String cacertsPasswd =
                        properties.getProperty(
                                "org.apache.ws.security.crypto.merlin.cacerts.password",
                                "changeit"
                        );
                this.cacerts = load(cacertsIs, cacertsPasswd, null, KeyStore.getDefaultType());
                if (doDebug) {
                    log.debug("CA certs have been loaded");
                }
            } finally {
                cacertsIs.close();
            }
        } else {
            if (doDebug) {
                log.debug("CA certs have not been loaded");
            }
        }
        */
    }

    protected String getCryptoProvider() {
        //return properties.getProperty("org.apache.ws.security.crypto.merlin.cert.provider");
        //todo
        return null;
    }

    //todo remove?:

    public String getDefaultX509Alias() {
        return defaultX509Alias;
    }

}
