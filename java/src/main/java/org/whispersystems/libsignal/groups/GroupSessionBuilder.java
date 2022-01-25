/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.groups;

import java.util.UUID;
import java.util.logging.Logger;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.groups.state.SenderKeyRecord;
import org.whispersystems.libsignal.groups.state.SenderKeyState;
import org.whispersystems.libsignal.groups.state.SenderKeyStore;
import org.whispersystems.libsignal.protocol.SenderKeyDistributionMessage;
import org.whispersystems.libsignal.util.KeyHelper;

/**
 * GroupSessionBuilder is responsible for setting up group SenderKey encrypted sessions.
 *
 * Once a session has been established, {@link org.whispersystems.libsignal.groups.GroupCipher}
 * can be used to encrypt/decrypt messages in that session.
 * <p>
 * The built sessions are unidirectional: they can be used either for sending or for receiving,
 * but not both.
 *
 * Sessions are constructed per (groupId + senderId + deviceId) tuple.  Remote logical users
 * are identified by their senderId, and each logical recipientId can have multiple physical
 * devices.
 *
 * @author Moxie Marlinspike
 */

public class GroupSessionBuilder {

  private final SenderKeyStore senderKeyStore;
  
  static final Logger logger = Logger.getLogger(GroupSessionBuilder.class.getName());
  
  public GroupSessionBuilder(SenderKeyStore senderKeyStore) {
    this.senderKeyStore = senderKeyStore;
  }

  /**
   * Construct a group session for receiving messages from senderKeyName.
   *
   * @param sender The address associated with the SenderKeyDistributionMessage.
   * @param senderKeyDistributionMessage A received SenderKeyDistributionMessage.
   */
  public void process( SignalProtocolAddress sender , SenderKeyDistributionMessage senderKeyDistributionMessage) {
    synchronized (GroupCipher.LOCK) {
        UUID uuid = senderKeyDistributionMessage.getDistributionUuid();
        logger.info("Process GroupSessionBuilder for UUID = "+uuid);
      SenderKeyRecord senderKeyRecord = senderKeyStore.loadSenderKey(sender, uuid);
      senderKeyRecord.addSenderKeyState(senderKeyDistributionMessage.getChainId(),
                                        senderKeyDistributionMessage.getIteration(),
                                        senderKeyDistributionMessage.getChainKey(),
                                        senderKeyDistributionMessage.getSignatureKey());
        logger.fine("SENDERKEYSTORE = "+this.senderKeyStore+" and record = "+senderKeyRecord);
      senderKeyStore.storeSenderKey(sender, uuid, senderKeyRecord);
        logger.fine("[GroupSessionBuilder] SenderKeyDistributionMessage stored "+uuid+", sender");
    }
  }

  /**
   * Construct a group session for sending messages.
   *
   * @param senderKeyName The (groupId, senderId, deviceId) tuple.  In this case, 'senderId' should be the caller.
   * @return A SenderKeyDistributionMessage that is individually distributed to each member of the group.
   */
//    public SenderKeyDistributionMessage create(SenderKeyName senderKeyName) {
  public SenderKeyDistributionMessage create(SignalProtocolAddress sender, UUID distributionId) {
    synchronized (GroupCipher.LOCK) {
      try {
        SenderKeyRecord senderKeyRecord = senderKeyStore.loadSenderKey(sender, distributionId);

        if (senderKeyRecord.isEmpty()) {
          senderKeyRecord.setSenderKeyState(KeyHelper.generateSenderKeyId(),
                                            0,
                                            KeyHelper.generateSenderKey(),
                                            KeyHelper.generateSenderSigningKey());
          senderKeyStore.storeSenderKey(sender, distributionId, senderKeyRecord);
        }

        SenderKeyState state = senderKeyRecord.getSenderKeyState();

        SenderKeyDistributionMessage answer = new SenderKeyDistributionMessage(state.getKeyId(),
                                                state.getSenderChainKey().getIteration(),
                                                state.getSenderChainKey().getSeed(),
                                                state.getSigningKeyPublic(), distributionId);
        return answer;

      } catch (InvalidKeyIdException | InvalidKeyException e) {
        throw new AssertionError(e);
      }
    }
  }
}
