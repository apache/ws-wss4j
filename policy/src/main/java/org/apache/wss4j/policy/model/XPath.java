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
package org.apache.wss4j.policy.model;

import java.util.Map;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class XPath {

    public enum Version {
        V1("1"),
        V2("2");

        private final String version;

        Version(String version) {
            this.version = version;
        }

        public String getVersion() {
            return version;
        }
    }

    private final String xPath;
    private final Version version;
    private final String filter;
    private final Map<String, String> prefixNamespaceMap;

    public XPath(String xPath, Version version, String filter, Map<String, String> prefixNamespaceMap) {
        this.xPath = xPath;
        this.version = version;
        this.filter = filter;
        this.prefixNamespaceMap = prefixNamespaceMap;
    }

    public String getXPath() {
        return xPath;
    }

    public Version getVersion() {
        return version;
    }

    public String getFilter() {
        return filter;
    }

    public Map<String, String> getPrefixNamespaceMap() {
        return prefixNamespaceMap;
    }
}
