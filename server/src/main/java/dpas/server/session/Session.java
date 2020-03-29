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

    public void nextSequenceNumber() {_sequenceNumber += 2;}

    public long getSequenceNumber() {
        return _sequenceNumber;
    }

    public PublicKey getPublicKey() {
        return _publicKey;
    }

    public String getSessionNonce() {
        return _sessionNonce;
    }

    public LocalDateTime getValidity() {
        return _validity;
    }

    public boolean isInvalid() {
        return LocalDateTime.now().isAfter(_validity);
    }

}
