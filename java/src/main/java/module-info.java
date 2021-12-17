module org.whispersystems.protocol {
    requires com.google.protobuf;
    requires org.whispersystems.curve25519;
    exports org.whispersystems.libsignal;
    exports org.whispersystems.libsignal.ecc;
    exports org.whispersystems.libsignal.groups;
    exports org.whispersystems.libsignal.groups.state;
    exports org.whispersystems.libsignal.kdf;
    exports org.whispersystems.libsignal.logging;
    exports org.whispersystems.libsignal.protocol;
    exports org.whispersystems.libsignal.ratchet;
    exports org.whispersystems.libsignal.state;
    exports org.whispersystems.libsignal.state.impl;
    exports org.whispersystems.libsignal.util;
}
