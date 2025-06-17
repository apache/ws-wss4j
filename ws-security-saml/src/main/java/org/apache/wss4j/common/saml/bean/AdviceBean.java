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

package org.apache.wss4j.common.saml.bean;

import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Element;


/**
 * Represents a SAML Advice Element.
 */
public class AdviceBean {

    private List<String> idReferences = new ArrayList<>();
    private List<String> uriReferences = new ArrayList<>();
    private List<Element> assertions = new ArrayList<>();

    public List<String> getIdReferences() {
        return idReferences;
    }

    public List<String> getUriReferences() {
        return uriReferences;
    }

    public List<Element> getAssertions() {
        return assertions;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof AdviceBean)) {
            return false;
        }

        AdviceBean that = (AdviceBean) o;

        if (idReferences == null && that.idReferences != null) {
            return false;
        } else if (idReferences != null && !idReferences.equals(that.idReferences)) {
            return false;
        }

        if (uriReferences == null && that.uriReferences != null) {
            return false;
        } else if (uriReferences != null && !uriReferences.equals(that.uriReferences)) {
            return false;
        }

        if (assertions == null && that.assertions != null) {
            return false;
        } else if (assertions != null && !assertions.equals(that.assertions)) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        int result = 0;
        if (idReferences != null) {
            result = 31 * result + idReferences.hashCode();
        }
        if (uriReferences != null) {
            result = 31 * result + uriReferences.hashCode();
        }
        if (assertions != null) {
            result = 31 * result + assertions.hashCode();
        }
        return result;
    }

}
