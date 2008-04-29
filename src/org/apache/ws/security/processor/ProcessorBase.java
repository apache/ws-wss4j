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

package org.apache.ws.security.processor;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

abstract class ProcessorBase implements Processor {

    
    /**
     * @return      the list of children of the supplied parent node.
     *              This operation is guaranteed to return a non-null
     *              (though possibly empty) list.
     */
    protected static java.util.List
    listChildren(
        final Node parent
    ) {
        if (parent == null) {
            return java.util.Collections.EMPTY_LIST;
        }
        final java.util.List ret = new java.util.ArrayList();
        if (parent.hasChildNodes()) {
            final NodeList children = parent.getChildNodes();
            if (children != null) {
                for (int i = 0, n = children.getLength();  i < n;  ++i) {
                    ret.add(children.item(i));
                }
            }
        }
        return ret;
    }
    
    /**
     * @return      a list of Nodes in b that are not in a (b - a)
     */
    protected static java.util.List
    newNodes(
        final java.util.List a,
        final java.util.List b
    ) {
        if (a.size() == 0) {
            return b;
        }
        if (b.size() == 0) {
            return java.util.Collections.EMPTY_LIST;
        }
        final java.util.List ret = new java.util.ArrayList();
        for (
            final java.util.Iterator bpos = b.iterator();
            bpos.hasNext();
        ) {
            final Node bnode = (Node) bpos.next();
            boolean found = false;
            for (
                final java.util.Iterator apos = a.iterator();
                apos.hasNext();
            ) {
                final Node anode = (Node) apos.next();
                if (anode == bnode) {
                    found = true;
                }
            }
            if (!found) {
                ret.add(bnode);
            }
        }
        return ret;
    }
}
