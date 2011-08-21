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
package org.swssf.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.swssf.ext.Transformer;
import org.swssf.ext.Utils;
import org.swssf.ext.WSSecurityException;
import org.xmlsecurity.ns.configuration.TransformAlgorithmType;
import org.xmlsecurity.ns.configuration.TransformAlgorithmsType;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Mapping between JCE id and xmlsec uri's for algorithms
 * Class lent from apache santuario (xmlsec)
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class TransformerAlgorithmMapper {

    private static final transient Log logger = LogFactory.getLog(TransformerAlgorithmMapper.class);

    private static Map<String, TransformAlgorithmType> algorithmsMap;
    private static Map<String, Class<Transformer>> algorithmsClassMap;

    private TransformerAlgorithmMapper() {
    }

    @SuppressWarnings("unchecked")
    protected static void init(TransformAlgorithmsType transformAlgorithms) throws Exception {
        List<TransformAlgorithmType> algorithms = transformAlgorithms.getTransformAlgorithm();
        algorithmsMap = new HashMap<String, TransformAlgorithmType>(algorithms.size());
        algorithmsClassMap = new HashMap<String, Class<Transformer>>();

        for (int i = 0; i < algorithms.size(); i++) {
            TransformAlgorithmType algorithmType = algorithms.get(i);
            algorithmsMap.put(algorithmType.getURI(), algorithmType);
            algorithmsClassMap.put(algorithmType.getURI(), Utils.loadClass(algorithmType.getJAVACLASS()));
        }
    }

    public static Class<Transformer> getTransformerClass(String algoURI) throws WSSecurityException {
        Class<Transformer> clazz = algorithmsClassMap.get(algoURI);
        if (clazz == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK);
        }
        return clazz;
    }

    public static TransformAlgorithmType getAlgorithmMapping(String algoURI) {
        return algorithmsMap.get(algoURI);
    }
}
