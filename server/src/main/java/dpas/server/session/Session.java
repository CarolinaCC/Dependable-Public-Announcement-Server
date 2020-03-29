package dpas.server.session;

import java.security.PublicKey;
import java.time.LocalDateTime;

public class Session {
    private long _sequenceNumber;
    private PublicKey _publicKey;
    private String _sessionNonce;
    private LocalDateTime _validity;

    public Session(long _sequenceNumber, PublicKey _publicKey, String _sessionNonce, LocalDateTime _validity) {
        this._sequenceNumber = _sequenceNumber;
        this._publicKey = _publicKey;
        this._sessionNonce = _sessionNonce;
        this._validity = _validity;
    }

    public long get_sequenceNumber() {
        return _sequenceNumber;
    }

    public PublicKey get_publicKey() {
        return _publicKey;
    }

    public String get_sessionNonce() {
        return _sessionNonce;
    }

    public LocalDateTime get_validity() {
        return _validity;
    }

    public boolean isInvalid() {
        return LocalDateTime.now().isAfter(_validity);
    }

}
