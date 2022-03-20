/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.protocol;

import com.google.protobuf.ByteString;
import java.io.ByteArrayOutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.InvalidVersionException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.ecc.ECPublicKey;

public final class DecryptionErrorMessage {

    private final byte[] originalBytes;
    private final int messageType;
    private final long timestamp;
    private final int originalSenderDeviceId;
    private ECPublicKey ratchetKey;
    private static final Logger LOG = Logger.getLogger(DecryptionErrorMessage.class.getName());

    private DecryptionErrorMessage(byte[] originalBytes, int messageType, long timestamp, int originalSenderDeviceId) {
        this.originalBytes = originalBytes;
        this.messageType = messageType;
        this.timestamp = timestamp;
        this.originalSenderDeviceId = originalSenderDeviceId;
        try {
            switch (this.messageType) {
                case CiphertextMessage.WHISPER_TYPE:
                    SignalMessage sm = new SignalMessage(originalBytes);
                    this.ratchetKey = sm.getSenderRatchetKey();
                    break;
                case CiphertextMessage.PREKEY_TYPE:
                    PreKeySignalMessage pksm = new PreKeySignalMessage(originalBytes);
                    this.ratchetKey = pksm.getWhisperMessage().getSenderRatchetKey();
                    break;
                case CiphertextMessage.SENDERKEY_TYPE:
                    this.ratchetKey = null;
                    break;
                case CiphertextMessage.PLAINTEXT_CONTENT_TYPE:
                    throw new IllegalArgumentException("Cannot create a DecryptionErrorMessage for plaintext content; it is not encrypted");
            }

        } catch (InvalidMessageException ex) {
            LOG.log(Level.SEVERE, null, ex);
        } catch (InvalidVersionException ex) {
            LOG.log(Level.SEVERE, null, ex);
        } catch (LegacyMessageException ex) {
            LOG.log(Level.SEVERE, null, ex);
        }
    }

    public static DecryptionErrorMessage forOriginalMessage(byte[] originalBytes, int messageType, long timestamp, int originalSenderDeviceId) {
        return new DecryptionErrorMessage(originalBytes, messageType, timestamp, originalSenderDeviceId);
    }

    public byte[] serialize() {
        SignalProtos.DecryptionErrorMessage.Builder builder = 
                SignalProtos.DecryptionErrorMessage.newBuilder()
                .setDeviceId(originalSenderDeviceId)
                .setTimestamp(timestamp);
        if (this.ratchetKey != null) {
            builder.setRatchetKey(ByteString.copyFrom(ratchetKey.getPublicKeyBytes()));
        }
        return builder.build().toByteArray();
    }

}
/*

  final long unsafeHandle;

  @Override
  protected void finalize() {
     Native.DecryptionErrorMessage_Destroy(this.unsafeHandle);
  }

  public long unsafeNativeHandleWithoutGuard() {
    return unsafeHandle;
  }

  DecryptionErrorMessage(long unsafeHandle) {
    this.unsafeHandle = unsafeHandle;
  }

  public DecryptionErrorMessage(byte[] serialized) throws InvalidMessageException {
    this.unsafeHandle = Native.DecryptionErrorMessage_Deserialize(serialized);
  }

  public static DecryptionErrorMessage forOriginalMessage(byte[] originalBytes, int messageType, long timestamp, int originalSenderDeviceId) {
    return new DecryptionErrorMessage(
      Native.DecryptionErrorMessage_ForOriginalMessage(originalBytes, messageType, timestamp, originalSenderDeviceId));
  }

  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.DecryptionErrorMessage_GetSerialized(guard.nativeHandle());
    }
  }

  public Optional<ECPublicKey> getRatchetKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      long keyHandle = Native.DecryptionErrorMessage_GetRatchetKey(guard.nativeHandle());
      if (keyHandle == 0) {
        return Optional.absent();
      } else {
        return Optional.of(new ECPublicKey(keyHandle));
      }
    }
  }

  public long getTimestamp() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.DecryptionErrorMessage_GetTimestamp(guard.nativeHandle());
    }
  }

  public int getDeviceId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.DecryptionErrorMessage_GetDeviceId(guard.nativeHandle());
    }
  }

  /// For testing only
  public static DecryptionErrorMessage extractFromSerializedContent(byte[] serializedContentBytes) throws InvalidMessageException {
    return new DecryptionErrorMessage(
      Native.DecryptionErrorMessage_ExtractFromSerializedContent(serializedContentBytes));
  }
}
*/
