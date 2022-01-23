/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.protocol;

import java.io.ByteArrayOutputStream;

public final class DecryptionErrorMessage {

    private final byte[] originalBytes;
    private final int messageType;
    private final long timestamp;
    private final int originalSenderDeviceId;

    private DecryptionErrorMessage(byte[] originalBytes, int messageType, long timestamp, int originalSenderDeviceId) {
        this.originalBytes = originalBytes;
        this.messageType = messageType;
        this.timestamp = timestamp;
        this.originalSenderDeviceId = originalSenderDeviceId;
    }

    public static DecryptionErrorMessage forOriginalMessage(byte[] originalBytes, int messageType, long timestamp, int originalSenderDeviceId) {
        return new DecryptionErrorMessage(originalBytes, messageType, timestamp, originalSenderDeviceId);
    }
    
    public byte[] serialize() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.writeBytes(originalBytes);
        baos.writeBytes(intToBytes(messageType));
        baos.writeBytes(longToBytes(timestamp));
        baos.writeBytes(intToBytes(originalSenderDeviceId));
        return baos.toByteArray();
    }

    private byte[] intToBytes(int val) {
        byte[] answer = new byte[4];
        for (int i = 0; i < 4; i++) {
            answer[3 - i] = (byte) (val & 0xFF);
            val >>= 8;
        }
        return answer;
    }
    
    private byte[] longToBytes(long val) {
        byte[] answer = new byte[8];
        for (int i = 0; i < 8; i++) {
            answer[7 - i] = (byte) (val & 0xFF);
            val >>= 8;
        }
        return answer;
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
