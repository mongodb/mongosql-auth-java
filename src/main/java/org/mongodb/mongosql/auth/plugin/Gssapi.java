/*
 * Copyright 2008-2017 MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.mongodb.mongosql.auth.plugin;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.util.HashMap;
import java.util.Map;

final class Gssapi {
    private static final String SERVICE_NAME_DEFAULT_VALUE = "mongosql";
    private static final String GSSAPI_OID = "1.2.840.113554.1.2.2";

    static SaslClient createSaslClient(final String user, final String hostName, final String serviceName) throws SaslException {
        Map<String, Object> saslClientProperties = new HashMap<String, Object>();
        saslClientProperties.put(Sasl.MAX_BUFFER, "0");
        saslClientProperties.put(Sasl.CREDENTIALS, getGSSCredential(user));
        String saslServiceName = serviceName == null || serviceName.isEmpty() ? SERVICE_NAME_DEFAULT_VALUE : serviceName;
        return Sasl.createSaslClient(new String[]{"GSSAPI"}, user, saslServiceName , hostName, saslClientProperties, null);
    }

    private static GSSCredential getGSSCredential(final String userName) throws SaslException {
        try {
            Oid krb5Mechanism = new Oid(GSSAPI_OID);
            GSSManager manager = GSSManager.getInstance();
            GSSName name = manager.createName(userName, GSSName.NT_USER_NAME);
            return manager.createCredential(name, GSSCredential.INDEFINITE_LIFETIME, krb5Mechanism, GSSCredential.INITIATE_ONLY);
        } catch (GSSException e) {
            throw new SaslException("Unable to create GSSAPI credential", e);
        }
    }

    private Gssapi() {}
}
