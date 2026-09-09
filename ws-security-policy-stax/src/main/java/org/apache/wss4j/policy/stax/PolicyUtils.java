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
package org.apache.wss4j.policy.stax;

import org.apache.wss4j.common.WSSPolicyException;
import org.apache.wss4j.policy.model.XPath;
import org.apache.wss4j.stax.utils.WSSUtils;

import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public final class PolicyUtils {

    // Conservative approximation of an XML NCName; rejects wildcards ("*"), predicates
    // (e.g. "Body[1]") and functions, which getElementPath cannot represent as a QName step.
    private static final Pattern NCNAME_PATTERN = Pattern.compile("^[A-Za-z_][\\w.-]*$");

    private PolicyUtils() {
        // complete
    }

    /**
     * Parses an XPath into raw QName steps.
     */
    public static List<QName> getElementPath(XPath xPath) {
        try {
            return getElementPathDescriptor(xPath).getPath();
        } catch (WSSPolicyException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    /**
     * Parses a sp:XPath expression into validated element steps. Only chains of plain
     * prefix:localName (or localName) steps are supported, either absolute (leading "/") or
     * relative; wildcards, predicates, functions and descendant ("//") steps are rejected
     * instead of silently producing a path that could never match a real element (CWE-347).
     */
    public static ElementPath getElementPathDescriptor(XPath xPath) throws WSSPolicyException {
        String xPathString = xPath.getXPath();
        if (xPathString == null || xPathString.isEmpty()) {
            throw new WSSPolicyException("Empty XPath expression");
        }
        boolean absolute = xPathString.charAt(0) == '/';

        List<QName> elements = new ArrayList<>();
        String[] xPathElements = xPathString.split("/");
        for (int j = 0; j < xPathElements.length; j++) {
            String xPathElement = xPathElements[j];
            if (xPathElement.isEmpty()) {
                // only the leading '/' of an absolute path may produce an empty step;
                // any other empty step means a "//" descendant axis, which isn't supported
                if (absolute && j == 0) {
                    continue;
                }
                throw new WSSPolicyException(
                    "Unsupported XPath expression, descendant ('//') steps are not supported: " + xPathString);
            }
            String[] elementParts = xPathElement.split(":");
            if (elementParts.length == 2 && isNCName(elementParts[0]) && isNCName(elementParts[1])) {
                String ns = xPath.getPrefixNamespaceMap().get(elementParts[0]);
                if (ns == null) {
                    throw new WSSPolicyException("Namespace not declared for prefix: " + elementParts[0]);
                }
                elements.add(new QName(ns, elementParts[1]));
            } else if (elementParts.length == 1 && isNCName(elementParts[0])) {
                elements.add(new QName(elementParts[0]));
            } else {
                throw new WSSPolicyException(
                    "Unsupported XPath step (wildcards, predicates and functions are not supported): "
                        + xPathElement);
            }
        }
        return new ElementPath(elements, absolute);
    }

    private static boolean isNCName(String name) {
        return NCNAME_PATTERN.matcher(name).matches();
    }

    /**
     * Wraps an already fully-qualified, absolute element path (e.g. a well-known SOAP header
     * path built in code) as an ElementPath that must match the observed path exactly.
     */
    public static ElementPath absoluteElementPath(List<QName> path) {
        return new ElementPath(path, true);
    }

    /**
     * The element steps parsed from a sp:XPath expression. An absolute path must match the
     * observed element path exactly; a relative path must match its trailing steps (tail).
     */
    public static final class ElementPath {
        private final List<QName> path;
        private final boolean absolute;

        private ElementPath(List<QName> path, boolean absolute) {
            this.path = path;
            this.absolute = absolute;
        }

        public List<QName> getPath() {
            return path;
        }

        public boolean matches(List<QName> observedPath) {
            if (absolute) {
                return WSSUtils.pathMatches(path, observedPath);
            }
            if (observedPath == null || observedPath.size() < path.size()) {
                return false;
            }
            return WSSUtils.pathMatches(path, observedPath.subList(observedPath.size() - path.size(), observedPath.size()));
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof ElementPath)) {
                return false;
            }
            ElementPath other = (ElementPath) o;
            return absolute == other.absolute && path.equals(other.path);
        }

        @Override
        public int hashCode() {
            return path.hashCode() * 31 + (absolute ? 1 : 0);
        }
    }
}
