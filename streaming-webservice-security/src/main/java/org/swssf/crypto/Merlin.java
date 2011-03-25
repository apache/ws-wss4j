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
package org.swssf.crypto;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.swssf.config.ConfigurationProperties;

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

    /**
     * This allows providing a custom class loader to load the resources, etc
     *
     * @throws java.io.IOException
     */
    public Merlin() throws IOException {
    }

    protected String getCryptoProvider() {
        return ConfigurationProperties.getProperty("CertProvider");
    }

    public String getDefaultX509Alias() {
        return ConfigurationProperties.getProperty("DefaultX509Alias");
    }

}
