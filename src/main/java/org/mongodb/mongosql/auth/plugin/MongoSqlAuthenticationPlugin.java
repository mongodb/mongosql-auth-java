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

import com.mysql.jdbc.AuthenticationPlugin;
import com.mysql.jdbc.Buffer;
import com.mysql.jdbc.Connection;
import com.mysql.jdbc.SQLError;
import com.mysql.jdbc.StringUtils;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import static org.mongodb.mongosql.auth.plugin.BufferHelper.writeByte;
import static org.mongodb.mongosql.auth.plugin.BufferHelper.writeBytes;
import static org.mongodb.mongosql.auth.plugin.BufferHelper.writeInt;

/**
 * A MySQL authentication plugin that implements the client-side of all MongoDB-supported authentication mechanisms.
 *
 * @since 1.0
 */
public class MongoSqlAuthenticationPlugin implements AuthenticationPlugin {
    private String user;
    private String password;
    private boolean firstChallenge = true;
    private String hostName;
    private String serviceName;
    private final List<SaslClient> saslClients = new ArrayList<SaslClient>();

    @Override
    public String getProtocolPluginName() {
        return "mongosql_auth";
    }

    @Override
    public boolean requiresConfidentiality() {
        return false;
    }

    @Override
    public boolean isReusable() {
        return false;
    }

    @Override
    public void setAuthenticationParameters(final String user, final String password) {
        this.user = user.contains("?") ? user.substring(0, user.indexOf("?")) : user;
        this.password = password;
        this.serviceName = findParameter("serviceName", user);
    }

    @Override
    public void init(final Connection conn, final Properties props) throws SQLException {
        this.hostName = conn.getHost();
    }

    @Override
    public void destroy() {
        for (SaslClient saslClient : saslClients) {
            try {
                saslClient.dispose();
            } catch (SaslException e) {
                // ignore
            }
        }
    }

    @Override
    public boolean nextAuthenticationStep(final Buffer fromServer, final List<Buffer> toServer) throws SQLException {
        try {
            toServer.clear();

            if (fromServer == null) {
                throw SQLError.createSQLException("Unexpected empty challenge ", SQLError.SQL_STATE_GENERAL_ERROR, null);
            }

            if (firstChallenge) {
                firstChallenge = false;
                toServer.add(new Buffer(new byte[0]));
                return true;
            }

            ByteBuffer byteBuffer = ByteBuffer.wrap(fromServer.getByteBuffer(), 0, fromServer.getBufLength());
            byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
            if (saslClients.isEmpty()) {
                String mechanism = readString(byteBuffer);
                int iterations = byteBuffer.getInt();
                for (int i = 0; i < iterations; i++) {
                    saslClients.add(createSaslClient(mechanism));
                }
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            for (SaslClient saslClient : saslClients) {
                byte[] response = saslClient.evaluateChallenge(getNextChallenge(byteBuffer));

                writeByte(baos, (byte) (saslClient.isComplete() ? 1 : 0));
                writeInt(baos, response.length);
                writeBytes(baos, response);
            }

            toServer.add(new Buffer(baos.toByteArray()));

            return true; // The implementation of the authentication handshake requires that this method always returns true
        } catch (SaslException e) {
            throw SQLError.createSQLException("mongosql_auth authentication exception ", SQLError.SQL_STATE_GENERAL_ERROR, e, null);
        }
    }

    String getUser() {
        return user;
    }

    private SaslClient createSaslClient(final String mechanism) throws SaslException {
        if (mechanism.equals("SCRAM-SHA-1")) {
            return ScramSha1.createSaslClient(user, password);
        } else if (mechanism.equals("PLAIN")) {
            return Plain.createSaslClient(user, password);
        } else if (mechanism.equals("GSSAPI")) {
            return Gssapi.createSaslClient(user, hostName, serviceName);
        } else {
            throw new SaslException("Unsupported SASL mechanism " + mechanism);
        }
    }

    private String findParameter(final String target, final String search) {

        if (!search.contains(target)) return "";

        int startIdx = search.indexOf(target) + target.length();
        int paramStart = -1;
        int paramEnd = -1;
        for (int i = startIdx; i < search.length(); i++) {
            if (search.charAt(i) == '=') {
                paramStart = i + 1;
            }

            if (search.charAt(i) == '&') {
                paramEnd = i;
                break;
            }
        }

        if (paramStart == -1) {
            return "";
        }

        if (paramEnd == -1) {
            paramEnd = search.length();
        }

        return search.substring(paramStart, paramEnd);
    }
    
    private byte[] getNextChallenge(final ByteBuffer fromServer) {
        if (fromServer.remaining() == 0) {
            return new byte[0];
        }
        byte[] challengeBytes = new byte[fromServer.getInt()];
        fromServer.get(challengeBytes);
        return challengeBytes;
    }

    private String readString(final ByteBuffer byteBuffer) {
        int i = byteBuffer.position();
        int len = 0;
        int maxLen = byteBuffer.limit();

        while ((i < maxLen) && (byteBuffer.get(i) != 0)) {
            len++;
            i++;
        }

        String s = StringUtils.toString(byteBuffer.array(), byteBuffer.position(), len);
        byteBuffer.position(byteBuffer.position() + len + 1);

        return s;
    }
}
