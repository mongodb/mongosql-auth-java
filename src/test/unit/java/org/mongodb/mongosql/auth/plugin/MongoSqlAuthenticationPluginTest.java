/*
 * Copyright 2017 MongoDB, Inc.
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

import com.mysql.jdbc.Buffer;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;


public class MongoSqlAuthenticationPluginTest {

    private static final Charset UTF_8 = Charset.forName("UTF-8");

    @Test
    public void testProperties() {
        // given
        MongoSqlAuthenticationPlugin plugin = new MongoSqlAuthenticationPlugin();

        // then
        assertFalse(plugin.isReusable());
        assertFalse(plugin.requiresConfidentiality());
        assertEquals("mongosql_auth", plugin.getProtocolPluginName());
    }

    @Test
    public void shouldParseSimpleUserName() {
        // given
        MongoSqlAuthenticationPlugin plugin = new MongoSqlAuthenticationPlugin();

        // when
        plugin.setAuthenticationParameters("testUser", "pwd");

        // then
        assertEquals("testUser", plugin.getUser());
    }

    @Test
    public void shouldParseUserNameWithQueryParameters() {
        // given
        MongoSqlAuthenticationPlugin plugin = new MongoSqlAuthenticationPlugin();

        // when
        plugin.setAuthenticationParameters("testUser?apples?mechanism=PLAIN&authSource=test", "pwd");

        // then
        assertEquals("testUser", plugin.getUser());
    }

    @Test
    public void shouldParseServiceNameWithMultipleQueryParameters() {
        // given
        MongoSqlAuthenticationPlugin plugin = new MongoSqlAuthenticationPlugin();

        // when
        plugin.setAuthenticationParameters("testUser?mechanism=GSSAPI&authSource=test&serviceName=blah", "pwd");

        // then
        assertEquals("blah", plugin.getServiceName());

        // when
        plugin.setAuthenticationParameters("testUser?mechanism=GSSAPI&serviceName=blah&stuff", "pwd");

        // then
        assertEquals("blah", plugin.getServiceName());

        // when
        plugin.setAuthenticationParameters("testUser?mechanism=GSSAPI&serviceName=", "pwd");

        // then
        assertEquals("", plugin.getServiceName());

        // when
        plugin.setAuthenticationParameters("testUser?mechanism=GSSAPI&serviceName=x&serviceName=y", "pwd");

        // then
        assertEquals("x", plugin.getServiceName());

        // when
        plugin.setAuthenticationParameters("testUser?mechanism=GSSAPI&stuffserviceName=x", "pwd");

        // then
        assertNull(plugin.getServiceName());

        // when
        plugin.setAuthenticationParameters("testUser?mechanism=GSSAPI&serviceNameBlah=x", "pwd");

        // then
        assertNull(plugin.getServiceName());

        // when
        plugin.setAuthenticationParameters("testUser?mechanism=GSSAPI", "pwd");

        // then
        assertNull(plugin.getServiceName());
    }

    @Test
    public void testAuthenticationWithMultipleIterations() throws SQLException {
        // given
        String mechanism = "PLAIN";
        String user = "testUser";
        String pwd = "pwd";
        MongoSqlAuthenticationPlugin plugin = new MongoSqlAuthenticationPlugin();
        plugin.setAuthenticationParameters(user + "?mechanism=" + mechanism, pwd);

        Buffer fromServer = new Buffer(new byte[21]);
        List<Buffer> toServer = new ArrayList<Buffer>();

        // when initial challenge
        boolean done = plugin.nextAuthenticationStep(fromServer, toServer);

        // then
        assertTrue(done);
        assertEquals(1, toServer.size());
        assertArrayEquals(toServer.get(0).getByteBuffer(), new byte[0]);

        ByteBuffer buffer = ByteBuffer.allocate(mechanism.length() + 5);
        buffer.put(mechanism.getBytes(UTF_8));
        buffer.put((byte) 0);                  // null terminate the mechanism
        buffer.put(intAsByteArray(2));   // 2 iterations
        fromServer = new Buffer(buffer.array());
        toServer = new ArrayList<Buffer>();

        // when
        done = plugin.nextAuthenticationStep(fromServer, toServer);

        // then
        assertTrue(done);
        assertEquals(1, toServer.size());
        assertArrayEquals(toServer.get(0).getByteBuffer(),
                concat(
                        new byte[]{1, 21, 0, 0, 0}, user.getBytes(UTF_8), nullStart(user.getBytes(UTF_8)), nullStart(pwd.getBytes(UTF_8)),
                        new byte[]{1, 21, 0, 0, 0}, user.getBytes(UTF_8), nullStart(user.getBytes(UTF_8)), nullStart(pwd.getBytes(UTF_8))));
    }

    private static byte[] concat(final byte[] first, final byte[]... rest) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(first);
            for (byte[] cur : rest) {
                baos.write(cur);
            }
            return baos.toByteArray();
        } catch (IOException e) {
            // can't happen
            throw new RuntimeException(e);
        }
    }

    private static byte[] nullStart(final byte[] nonceBytes) {
        byte[] challengeBytes = new byte[nonceBytes.length + 1];
        System.arraycopy(nonceBytes, 0, challengeBytes, 1, nonceBytes.length);
        return challengeBytes;
    }

    private static byte[] intAsByteArray(final int value) {
        ByteBuffer byteBuffer = ByteBuffer.wrap(new byte[4]);
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
        byteBuffer.putInt(value);
        return byteBuffer.array();
    }
}
