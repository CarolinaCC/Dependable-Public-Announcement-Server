package dpas.library;

public class Session {
    private String sessionNonce;
    private long seq;

    public Session(String sessionNonce, long seq) {
        this.sessionNonce = sessionNonce;
        this.seq = seq;
    }

    public String getSessionNonce() {
        return sessionNonce;
    }

    public long getSeq() {
        return seq;
    }
}

