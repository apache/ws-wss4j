/**
 * Copyright 2010, 2011 Marc Giger
 *
 * This file is part of the streaming-webservice-security-framework (swssf).
 *
 * The streaming-webservice-security-framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The streaming-webservice-security-framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the streaming-webservice-security-framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.ext;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

/**
 * Class to describe which and how an element must be secured
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SecurePart {

    public enum Modifier {
        Element("http://www.w3.org/2001/04/xmlenc#Element"),
        Content("http://www.w3.org/2001/04/xmlenc#Content");

        private String modifier;

        Modifier(String modifier) {
            this.modifier = modifier;
        }

        public String getModifier() {
            return this.modifier;
        }

        private static final Map<String, Modifier> modifierMap = new HashMap<String, Modifier>();

        static {
            for (Modifier modifier : EnumSet.allOf(Modifier.class)) {
                modifierMap.put(modifier.getModifier(), modifier);
            }
        }

        public static Modifier getModifier(String modifier) {
            return modifierMap.get(modifier);
        }
    }

    private String name;
    private String namespace;
    private Modifier modifier;
    private String idToSign;
    private String idToReference;

    public SecurePart(String name, String namespace, Modifier modifier) {
        this.name = name;
        this.namespace = namespace;
        this.modifier = modifier;
    }

    public SecurePart(String name, String namespace, Modifier modifier, String idToSign) {
        this.name = name;
        this.namespace = namespace;
        this.modifier = modifier;
        this.idToSign = idToSign;
    }

    public SecurePart(String name, String namespace, Modifier modifier, String idToSign, String idToReference) {
        this.name = name;
        this.namespace = namespace;
        this.modifier = modifier;
        this.idToSign = idToSign;
        this.idToReference = idToReference;
    }

    /**
     * The name of the element to be secured
     *
     * @return The Element-Local-Name
     */
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    /**
     * The namespace of the element to be secured
     *
     * @return The Element Namespace
     */
    public String getNamespace() {
        return namespace;
    }

    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }

    /**
     * The Modifier: Element or Content
     *
     * @return The String "Element" or "Content"
     */
    public Modifier getModifier() {
        return modifier;
    }

    public void setModifier(Modifier modifier) {
        this.modifier = modifier;
    }

    /**
     * The id of the Element
     *
     * @return The id
     */
    public String getIdToSign() {
        return idToSign;
    }

    public void setIdToSign(String idToSign) {
        this.idToSign = idToSign;
    }

    public String getIdToReference() {
        return idToReference;
    }

    public void setIdToReference(String idToReference) {
        this.idToReference = idToReference;
    }
}
