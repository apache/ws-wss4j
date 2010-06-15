package ch.gigerstyle.xmlsec;

import javax.xml.stream.events.Namespace;

/**
 * User: giger
 * Date: May 19, 2010
 * Time: 5:39:24 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class ComparableNamespace implements Comparable<ComparableNamespace> {

    private Namespace namespace;

    public ComparableNamespace(Namespace namespace) {
        this.namespace = namespace;
    }

    public Namespace getNamespace() {
        return namespace;
    }

    public int compareTo(ComparableNamespace o) {
        //An element's namespace nodes are sorted lexicographically by local name
        //(the default namespace node, if one exists, has no local name and is therefore lexicographically least).
        int prefixCompare = this.getPrefix().compareTo(o.getPrefix());
//        if (prefixCompare != 0) {
            return prefixCompare;
/*        } else {
            return this.getNamespaceURI().compareTo(o.getNamespaceURI());
        }
        */
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof ComparableNamespace)) {
            return false;
        }
        ComparableNamespace comparableNamespace = (ComparableNamespace)obj;
        /*
        if (comparableNamespace.getPrefix().length() == 0 && this.getPrefix().length() == 0) {
            return comparableNamespace.getNamespaceURI().equals(this.getNamespaceURI());
        }
        else */if (comparableNamespace.getPrefix().equals(this.getPrefix())) {
                //&& comparableNamespace.getNamespaceURI().equals(this.getNamespaceURI())) {
            //just test for prefix to get the last prefix definition on the stack and let overwrite it 
            return true;
        }
        return false;
    }

    public String getPrefix() {
        return namespace.getPrefix();
    }

    public String getNamespaceURI() {
        return namespace.getNamespaceURI();
    }

    public boolean isDefaultNamespaceDeclaration() {
        return namespace.isDefaultNamespaceDeclaration();
    }

    @Override
    public String toString() {
        if (namespace.getPrefix() == null || namespace.getPrefix().length() == 0) {
            return "xmlns=\"" + namespace.getNamespaceURI() + "\"";
        }
        return "xmlns:" + namespace.getPrefix() + "=\"" + namespace.getNamespaceURI() + "\""; 
    }
}
