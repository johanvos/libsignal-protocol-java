package org.whispersystems.libsignal.protocol;

import com.google.protobuf.ByteString;


/**
 *
 * @author johan
 */
public class PlaintextContent implements CiphertextMessage {
    static final byte PLAINTEXT_CONTEXT_IDENTIFIER_BYTE = (byte)0xc0;
    static final byte PADDING_BOUNDARY_BYTE = (byte)0x80;
    
    byte[] serialized;
    byte[] body;
    
    public PlaintextContent(DecryptionErrorMessage message) {
        SignalProtos.Content content = SignalProtos.Content.newBuilder()
                .setDecryptionErrorMessage(ByteString.copyFrom(message.serialize()))
                .build();
        byte[] aserialized = content.toByteArray();
        int ol = aserialized.length;
        this.serialized = new byte[ol + 2];
        System.arraycopy(aserialized, 0, this.serialized, 1, ol);
        serialized[0] = PLAINTEXT_CONTEXT_IDENTIFIER_BYTE;
        serialized[ol + 1] = PADDING_BOUNDARY_BYTE;
        body = new byte[ol + 1];
        System.arraycopy(serialized, 1, body, 0, ol + 1);
    }

    public PlaintextContent(byte[] content) {
        int cl = content.length;
        this.body = new byte[cl -1];
        System.arraycopy(content, 1, body, 0, cl-1);
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
        return this.body;
    }
    
}
