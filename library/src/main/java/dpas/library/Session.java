package dpas.library;

public class Session {
    private long seq;

    public Session(long seq) {
        this.seq = seq;
    }

    public long getSeq() {
        return seq;
    }

    public void updateSeq() {
        seq += 1;
    }
}

