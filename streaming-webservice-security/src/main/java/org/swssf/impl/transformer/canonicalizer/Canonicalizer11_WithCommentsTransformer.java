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
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class Canonicalizer11_WithCommentsTransformer extends CanonicalizerBase {

    /**
     * Canonicalizer not complete. We are missing special handling for xml:base. But since
     * we don't support document subsets we don't need it!
     *
     * @param inclusiveNamespaces
     */
    public Canonicalizer11_WithCommentsTransformer(String inclusiveNamespaces) {
        super(inclusiveNamespaces, true);
    }

    @Override
    @SuppressWarnings("unchecked")
    protected List<ComparableNamespace>[] getInitialNamespaces(XMLEventNS xmlEventNS) {
        return xmlEventNS.getNamespaceList();
    }

    @Override
    @SuppressWarnings("unchecked")
    protected List<ComparableAttribute>[] getInitialAttributes(XMLEventNS xmlEventNS) {
        return xmlEventNS.getAttributeList();
    }

    @Override
    protected boolean namespaceIsVisibleUtilized(StartElement startElement, ComparableNamespace comparableNamespace) {
        return true;
    }

    protected SortedSet<ComparableAttribute> getUtilizedAttributes(StartElement startElement, List<ComparableAttribute>[] visibleAttributeList, C14NStack<List<Comparable>> outputStack) {
        SortedSet<ComparableAttribute> utilizedAttributes = new TreeSet<ComparableAttribute>();
        for (int i = 0; i < visibleAttributeList.length; i++) {
            List<ComparableAttribute> comparableAttributes = visibleAttributeList[i];
            for (int j = 0; j < comparableAttributes.size(); j++) {
                ComparableAttribute comparableAttribute = comparableAttributes.get(j);
                //xml:id attributes must be handled like other attributes: emit but dont inherit
                if (XML.equals(comparableAttribute.getName().getPrefix())
                        && ("id".equals(comparableAttribute.getName().getLocalPart()))
                        || ("base".equals(comparableAttribute.getName().getLocalPart()))) {
                    continue;
                }
                if (outputStack.containsOnStack(comparableAttribute) != null) {
                    continue;
                }
                utilizedAttributes.add(comparableAttribute);
                outputStack.peek().add(comparableAttribute);
            }
        }
        @SuppressWarnings("unchecked")
        Iterator<Attribute> attributesIterator = startElement.getAttributes();
        while (attributesIterator.hasNext()) {
            Attribute attribute = attributesIterator.next();
            //attributes with xml prefix are already processed in the for loop above
            //xml:id attributes must be handled like other attributes: emit but dont inherit
            if (XML.equals(attribute.getName().getPrefix())
                    && !"id".equals(attribute.getName().getLocalPart())
                    && !"base".equals(attribute.getName().getLocalPart())) {
                continue;
            }

            utilizedAttributes.add(new ComparableAttribute(attribute.getName(), attribute.getValue()));
        }
        return utilizedAttributes;
    }
}
