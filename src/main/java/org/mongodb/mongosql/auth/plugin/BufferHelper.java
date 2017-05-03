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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.sql.SQLException;

final class BufferHelper {
    static final Charset UTF_8 = Charset.forName("UTF-8");

    static void writeBytes(final ByteArrayOutputStream baos, final byte[] bytes) {
        try {
            baos.write(bytes);
        } catch (IOException e) {
            // impossible
            throw new RuntimeException("ByteArrayOutputStream doesn't throw IOExeption!", e);
        }
    }

    static void writeByte(final ByteArrayOutputStream baos, final byte b) throws SQLException {
        baos.write(b);
    }

    static void writeInt(final ByteArrayOutputStream baos, final int i) throws SQLException {
        ByteBuffer sizeBuffer = ByteBuffer.allocate(4);
        sizeBuffer.order(ByteOrder.LITTLE_ENDIAN);
        sizeBuffer.putInt(i);
        BufferHelper.writeBytes(baos, sizeBuffer.array());
    }

    private BufferHelper() {
    }
}
