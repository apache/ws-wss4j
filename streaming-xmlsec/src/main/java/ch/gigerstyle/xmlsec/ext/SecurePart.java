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
package ch.gigerstyle.xmlsec.ext;

/**
 * Class to describe which and how an element must be secured
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SecurePart {

    private String name;
    private String namespace;
    private String modifier;
    private String id;

    public SecurePart(String name, String namespace, String modifier) {
        this.name = name;
        this.namespace = namespace;
        this.modifier = modifier;
    }

    public SecurePart(String name, String namespace, String modifier, String id) {
        this.name = name;
        this.namespace = namespace;
        this.modifier = modifier;
        this.id = id;
    }

    /**
     * The name of the element to be secured
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
     * @return The String "Element" or "Content"
     */
    public String getModifier() {
        return modifier;
    }

    public void setModifier(String modifier) {
        this.modifier = modifier;
    }

    /**
     * The id of the Element
     * @return The id
     */
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }
}
