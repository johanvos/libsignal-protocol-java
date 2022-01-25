/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.whispersystems.libsignal.protocol;
//import org.whispersystems.libsignal.protocol.SignalProtos.DecryptionErrorMessage;

/**
 *
 * @author johan
 */
public class PlaintextContent implements CiphertextMessage {
    static final byte PLAINTEXT_CONTEXT_IDENTIFIER_BYTE = (byte)0xc0;
    static final byte PADDING_BOUNDARY_BYTE = (byte)0x80;
    
    byte[] serialized;
    private final DecryptionErrorMessage message;
    
      public PlaintextContent(DecryptionErrorMessage message) {
          this.message = message;
          this.serialized = message.serialize();
      }
      
    @Override
    public byte[] serialize() {
        return serialized;
    }

    @Override
    public int getType() {
        return PLAINTEXT_CONTENT_TYPE;
    }
    
    public byte[] getBody() {
        return this.serialized;
    }
    
}
