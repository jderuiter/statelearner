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

import java.io.BufferedOutputStream;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class TLSClient  implements Runnable {
    private Process p;
    private volatile boolean finished = false;

    public TLSClient(Process p) {
    	finished = false;
        this.p = p;
        new Thread(this).start();
    }

    public boolean isFinished() {
        return finished;
    }

    public void run() {
		try {
			Thread.sleep(10);

			BufferedOutputStream out = new BufferedOutputStream(p.getOutputStream());

			out.write("GET / HTTP/1.0\n\n".getBytes());
			out.flush();
			out.close();
			
			p.waitFor();
		} catch (Exception e) {
			finished = true;
		}
		finally {
			finished = true;
		}
    }
    
    public void kill() {
    	p.destroy();
    }

}