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

import org.junit.Test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import static org.junit.Assume.assumeTrue;

public class MongoSqlAuthenticationPluginFunctionalTest {

    private String host = System.getProperty("org.mongodb.test.host", "127.0.0.1");
    private String port = System.getProperty("org.mongodb.test.port", "3307");
    private String ssl = System.getProperty("org.mongodb.test.ssl", "false");
    private String database = System.getProperty("org.mongodb.test.database", "use_test");
    private String sql = System.getProperty("org.mongodb.test.sql", "select a from foo");
    private String url = "jdbc:mysql://" + host + ":" + port
                         + "?useSSL=" + ssl
                         + "&authenticationPlugins=org.mongodb.mongosql.auth.plugin.MongoSqlAuthenticationPlugin";

    private String user = System.getProperty("org.mongodb.test.user");
    private String password = System.getProperty("org.mongodb.test.password");


    @Test(expected = SQLException.class)
    public void testUnsuccessfulAuthentication() throws SQLException {
        assumeTrue(!"".equals(user));
        DriverManager.getConnection(url, user, "bad password");
    }

    @Test
    public void testSuccessfulAuthentication() throws SQLException {
        assumeTrue(!"".equals(user));

        Connection connection = DriverManager.getConnection(url, user, password);

        try {
            connection.setCatalog(database);

            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
            rs.next();
        } finally {
            connection.close();
        }

    }
}
