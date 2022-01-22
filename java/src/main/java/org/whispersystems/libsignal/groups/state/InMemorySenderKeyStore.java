package org.whispersystems.libsignal.groups.state;

import org.whispersystems.libsignal.groups.state.SenderKeyRecord;
import org.whispersystems.libsignal.groups.state.SenderKeyStore;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.util.Pair;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class InMemorySenderKeyStore implements SenderKeyStore {

  private final Map<Pair<SignalProtocolAddress, UUID>, SenderKeyRecord> store = new HashMap<>();

  @Override
  public void storeSenderKey(SignalProtocolAddress sender, UUID distributionId, SenderKeyRecord record) {
      System.err.println("store senderkey for "+sender+" and uuid = "+distributionId);
      store.put(new Pair(sender, distributionId), record);
  }

  @Override
  public SenderKeyRecord loadSenderKey(SignalProtocolAddress sender, UUID distributionId) {
            System.err.println("ask senderkey for "+sender+" and uuid = "+distributionId);

    try {
      SenderKeyRecord record = store.get(new Pair(sender, distributionId));

      if (record == null) {
System.err.println("no record found, db = " + store);
        return new SenderKeyRecord();
      } else {
        return new SenderKeyRecord(record.serialize());
      }
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }
}
