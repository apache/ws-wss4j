/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.impl.transformer.canonicalizer;

import org.swssf.ext.ComparableAttribute;
import org.swssf.ext.ComparableNamespace;
import org.swssf.ext.XMLEventNS;

import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.StartElement;
import java.util.Iterator;
import java.util.List;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class Canonicalizer20010315_ExclWithCommentsTransformer extends CanonicalizerBase {

    public Canonicalizer20010315_ExclWithCommentsTransformer(String inclusiveNamespaces) {
        super(inclusiveNamespaces, true);
    }

    @Override
    @SuppressWarnings("unchecked")
    protected List<ComparableNamespace>[] getInitialNamespaces(XMLEventNS xmlEventNS) {
        return new List[]{xmlEventNS.getNamespaceList()[0]};
    }

    @Override
    @SuppressWarnings("unchecked")
    protected List<ComparableAttribute>[] getInitialAttributes(XMLEventNS xmlEventNS) {
        return new List[]{xmlEventNS.getAttributeList()[0]};
    }

    @Override
    protected boolean namespaceIsVisibleUtilized(StartElement startElement, ComparableNamespace comparableNamespace) {
        //lookup if ns is used (visible utilized) in current element or in its attributes...
        if (comparableNamespace.getPrefix().equals(startElement.getName().getPrefix())) {
            return true;
        }
        @SuppressWarnings("unchecked")
        Iterator<Attribute> attrIterator = startElement.getAttributes();
        while (attrIterator.hasNext()) {
            Attribute attribute = attrIterator.next();
            if (comparableNamespace.getNamespaceURI().equals(attribute.getName().getNamespaceURI())) {
                return true;
            }
        }
        return false;
    }
}
