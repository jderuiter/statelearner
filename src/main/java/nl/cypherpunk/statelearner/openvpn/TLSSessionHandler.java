/*
 *  Copyright (c) 2017 Lesly-Ann Daniel
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

package nl.cypherpunk.statelearner.openvpn;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import nl.cypherpunk.statelearner.openvpn.messages.Ack;

/**
 * This class handles the acknowledgement mechanism of
 * multiple OpenVPN sessions from a single OpenVPN tunnel.
 * 
 * It keeps a list of the session-ids,
 * and the corresponding remote session-ids and packet-ids to acknowledge.
 */
public class TLSSessionHandler {
	List<AckSession> sessions;
	byte[] activeRemoteSid;
	byte[] authRemoteSid;
	/**
	 * The current packet id of the data channel
	 */
	private int dataPacketId;

	public TLSSessionHandler() {
		this.sessions = new ArrayList<>();
		this.dataPacketId = 1;
	}

	/**
	 * Add a fresh {@link AckSession} to the list, with the specified session-identifier.
	 * If an {@link AckSession} was already present in the list, with the same session
	 * identifier, the old one is removed from the list.
	 * @param sessionId the session-identifier of the new {@link AckSession}.
	 * @return the newly created {@link AckSession}.
	 */
	public AckSession addSession(byte[] sessionId) {
		AckSession session = new AckSession(sessionId);
		sessions.remove(session);
		sessions.add(session);
		return session;
	}
	
	public void incrDataPacketId() {
		++this.dataPacketId;
	}

	/**
	 * Get from the list the {@link AckSession} corresponding to the specified session-identifier.
	 * @param sessionId the session-identifier of the required {@link AckSession}.
	 * @return the first {@link AckSession} from the list that matches the specified session-identifier.
	 */
	public AckSession getSession(byte[] sessionId) {
		for(AckSession session : sessions) {
			if(Arrays.equals(session.getSessionId(), sessionId)) {
				return session;
			}
		}
		return null;
	}

	/**
	 * Remove from the list the {@link AckSession} corresponding to the specified session-identifier.
	 * @param sessionId the session-identifier of the {@link AckSession} to remove.
	 */
	public void removeSession(byte[] sessionId) {
		for(AckSession session : sessions) {
			if(Arrays.equals(session.getSessionId(), sessionId)) {
				sessions.remove(session);
			}
		}
	}

	/**
	 * Add a new message to acknowledge to the {@link AckSession}
	 * wich session-identifier matches the {@code sessionId} parameter.
	 * @param sessionId the local session-identifier to acknowledge.
	 * @param pid the packet-identifier of the packet to acknowledge
	 */
	public void addPid(byte[] sessionId, byte[] pid) {
		for(AckSession session : sessions) {
			if(Arrays.equals(session.getSessionId(), sessionId)) {
				session.add(pid);
				return;
			}
		}
		throw new IllegalArgumentException("Unknown local session-id: " + sessionId);
	}

	/**
	 * Clears the list, removing all the previously added {@link AckSession sessions}
	 * and the registered remote session-identifiers.
	 */
	public void clear() {
		this.sessions.clear();
		this.authRemoteSid = null;
		this.activeRemoteSid = null;
	}

	/**
	 * Returns all the {@link Ack} messages,
	 * needed to acknowledge all the pending packets.
	 * @return
	 */
	public List<Ack> getAckList() {
		List<Ack> ackList = new ArrayList<>();
		for(AckSession session: sessions) {
			Ack ack = session.getAck();
			if(ack != null) {
				ackList.add(ack);
			}
		}
		return ackList;
	}
	
	/**
	 * Clear the ack list, removing all the packet to acknowledge
	 * from all the sessions in the session list.
	 * This method must be called after {@link getAckList}
	 * to clear the list of the packets to acknowledge,
	 * when all the generated Ack messages are sent.
	 */
	public void clearAckList() {
		for(AckSession session: sessions) {
			session.clearAck();
		}
	}
	
	public void predictRemoteSid(byte[] sessionId) {
		if(authRemoteSid != null) {
			for(AckSession session : sessions) {
				if(Arrays.equals(session.getSessionId(), sessionId)) {
					if(session.remoteSessionId == null || !Arrays.equals(session.remoteSessionId, activeRemoteSid)) {
						session.remoteSessionId = authRemoteSid;
					}
				}
			}
		}
	}
	
	public void addRemoteSid(byte[] sessionId, byte[] remoteSid) {
		for(AckSession session : sessions) {
			if(Arrays.equals(session.getSessionId(), sessionId)) {
				session.remoteSessionId = remoteSid;
			}
		}
		if(activeRemoteSid == null) {
			activeRemoteSid = remoteSid;
		} else if(authRemoteSid == null) {
			authRemoteSid = remoteSid;
		} else {
			activeRemoteSid = authRemoteSid;
			authRemoteSid = remoteSid;
		}
	}

	/**
	 * Represent an OpenVPN TLS session, identified by its local {@code sessionId}.
	 */
	public class AckSession {
		/**
		 * The local identifier of the TLS session.
		 */
		private byte[] sessionId;
		/**
		 * The local packet identifier.
		 */
		private int packetId;
		/**
		 * The remote session identifier.
		 */
		private byte[] remoteSessionId;
		/**
		 * The list of the packet-id to acknowledge.
		 */
		private List<byte[]> pids;

		AckSession(byte[] sessionId) {
			this.sessionId = Arrays.copyOf(sessionId, sessionId.length);
			this.resetPacketId();
			this.pids = new ArrayList<>();
			this.remoteSessionId = new byte[8];
			Arrays.fill(this.remoteSessionId, (byte) 0);
		}

		/**
		 * Clears the list of the packets to acknowledge.
		 */
		public void clearAck() {
			pids.clear();
		}

		public byte[] getSessionId() {
			return this.sessionId;
		}

		public byte[] getPacketId() {
			return ByteBuffer.allocate(4).putInt(packetId).array();
		}

		public void incrPacketId() {
			++this.packetId;
		}

		public byte[] getRemoteSessionId() {
			return this.remoteSessionId;
		}

		/*public void setRemoteSessionId(byte[] remoteSessionId) {
			this.remoteSessionId = Arrays.copyOf(remoteSessionId, remoteSessionId.length);
		}*/

		/**
		 * Add a packet-id to acknowledge in the list.
		 * @param packetId the packet-id to acknowledge.
		 */
		public void add(byte[] packetId) {
			this.pids.add(packetId);
		}

		/**
		 * Reset the session, clearing the list of the messages to acknowledge
		 * and resetting the packet-id to 0.
		 */
		public void reset() {
			this.resetPacketId();
			pids.clear();
		}

		/**
		 * Return the {@link Ack} message that acknowledges all the pending packets of this session.
		 * @return the {@link Ack} message. 
		 */
		public Ack getAck() {
			if(pids.isEmpty()) {
				return null;
			}
			byte[] ackPacketId = new byte [pids.size() * 4];
			int n = 0;
			for(byte[] packetId : pids) {
				for(int i = 0; i < packetId.length; ++i) {
					ackPacketId[n] = packetId[i];
					++n;
				}
			}
			return new Ack(sessionId, ackPacketId, remoteSessionId);
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + getOuterType().hashCode();
			result = prime * result + Arrays.hashCode(sessionId);
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			AckSession other = (AckSession) obj;
			if (!getOuterType().equals(other.getOuterType()))
				return false;
			if (!Arrays.equals(sessionId, other.sessionId))
				return false;
			return true;
		}

		private TLSSessionHandler getOuterType() {
			return TLSSessionHandler.this;
		}

		public void resetPacketId() {
			this.packetId = 0;
		}

		public byte[] getDataPacketId() {
			return ByteBuffer.allocate(4).putInt(dataPacketId).array();
		}
	}
}
