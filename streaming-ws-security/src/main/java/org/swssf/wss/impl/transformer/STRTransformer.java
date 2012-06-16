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
package org.swssf.wss.impl.transformer;

import org.swssf.xmlsec.ext.Transformer;
import org.swssf.xmlsec.ext.XMLSecurityException;
import org.swssf.xmlsec.ext.stax.XMLSecEvent;

import javax.xml.stream.XMLStreamException;
import java.io.OutputStream;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class STRTransformer implements Transformer {

    private Transformer transformer;

    public STRTransformer() {
    }

    @Override
    public void setOutputStream(OutputStream outputStream) throws XMLSecurityException {
        throw new UnsupportedOperationException("OutputStream not supported");
    }

    @Override
    public void setList(List list) throws XMLSecurityException {
        throw new UnsupportedOperationException("List not supported");
    }

    @Override
    public void setTransformer(Transformer transformer) throws XMLSecurityException {
        this.transformer = transformer;
    }

    public void transform(XMLSecEvent xmlSecEvent) throws XMLStreamException {
        this.transformer.transform(xmlSecEvent);
    }
}
