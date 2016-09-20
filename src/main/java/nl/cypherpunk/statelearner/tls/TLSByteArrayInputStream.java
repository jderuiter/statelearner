/*
 *  Copyright (c) 2016 Joeri de Ruiter
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package nl.cypherpunk.statelearner.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class TLSByteArrayInputStream extends ByteArrayInputStream {
    /*
     * Read 8, 16, 24, and 32 bit SSL integer data types, encoded
     * in standard big-endian form.
     */

    public TLSByteArrayInputStream(byte[] buf) {
		super(buf);
	}

	public TLSByteArrayInputStream(byte[] buf, int offset, int len) {
		super(buf, offset, len);
	}

	public int getInt8() throws IOException {
        return read();
    }

	public int getInt16() throws IOException {
        return (getInt8() << 8) | getInt8();
    }

    public int getInt24() throws IOException {
        return (getInt8() << 16) | (getInt8() << 8) | getInt8();
    }

    public int getInt32() throws IOException {
        return (getInt8() << 24) | (getInt8() << 16)
             | (getInt8() << 8) | getInt8();
    }

    /*
     * Read byte vectors with 8, 16, and 24 bit length encodings.
     */

    public byte[] getBytes8() throws IOException {
        int len = getInt8();
        byte b[] = new byte[len];

        read(b, 0, len);
        return b;
    }

    public byte[] getBytes16() throws IOException {
        int len = getInt16();
        byte b[] = new byte[len];

        read(b, 0, len);
        return b;
    }

    public byte[] getBytes24() throws IOException {
        int len = getInt24();
        byte b[] = new byte[len];

        read(b, 0, len);
        return b;
    }
}
