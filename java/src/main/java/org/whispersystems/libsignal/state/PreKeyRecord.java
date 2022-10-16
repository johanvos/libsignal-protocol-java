/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.whispersystems.libsignal.InvalidMessageException;

import static org.whispersystems.libsignal.state.StorageProtos.PreKeyRecordStructure;

public class PreKeyRecord {

  private PreKeyRecordStructure structure;

  public PreKeyRecord(int id, ECKeyPair keyPair) {
    this.structure = PreKeyRecordStructure.newBuilder()
                                          .setId(id)
                                          .setPublicKey(ByteString.copyFrom(keyPair.getPublicKey()
                                                                                   .serialize()))
                                          .setPrivateKey(ByteString.copyFrom(keyPair.getPrivateKey()
                                                                                    .serialize()))
                                          .build();
  }

  public PreKeyRecord(byte[] serialized) throws InvalidMessageException {
      try {
          this.structure = PreKeyRecordStructure.parseFrom(serialized);
      } catch (InvalidProtocolBufferException ex) {
          throw new InvalidMessageException(ex);
      }
  }

  public int getId() {
    return this.structure.getId();
  }

  public ECKeyPair getKeyPair() {
    try {
      ECPublicKey publicKey = Curve.decodePoint(this.structure.getPublicKey().toByteArray(), 0);
      ECPrivateKey privateKey = Curve.decodePrivatePoint(this.structure.getPrivateKey().toByteArray());

      return new ECKeyPair(publicKey, privateKey);
    } catch (InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  public byte[] serialize() {
    return this.structure.toByteArray();
  }
}
