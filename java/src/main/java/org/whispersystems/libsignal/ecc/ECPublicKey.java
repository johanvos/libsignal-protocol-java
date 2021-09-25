/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.ecc;

public interface ECPublicKey extends Comparable<ECPublicKey> {

  public static final int KEY_SIZE = 33;

  public byte[] serialize();

  public byte[] getPublicKeyBytes();

  public int getType();

  static ECPublicKey fromPublicKeyBytes(byte[] b) {
    throw new RuntimeException("Fix this in a better way");
  }
}
