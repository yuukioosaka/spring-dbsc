package click.yukio.dbsc.core;

/**
 * Discriminator on {@link BoundKey}. A single session can hold two keys: the
 * native TPM/hardware key used by the W3C DBSC refresh flow, and the polyfill
 * ECDSA key used by the bound protocol and per-request proofs.
 */
public enum BoundKeyKind {
    NATIVE("native"),
    BOUND("bound");

    private final String wireValue;

    BoundKeyKind(String wireValue) {
        this.wireValue = wireValue;
    }

    public String wireValue() {
        return wireValue;
    }

    public static BoundKeyKind fromWire(String value) {
        if (value == null) {
            return NATIVE;
        }
        return "bound".equals(value) ? BOUND : NATIVE;
    }
}
