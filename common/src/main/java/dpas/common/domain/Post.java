package dpas.common.domain;

import dpas.common.domain.exception.NullMessageException;
import dpas.common.domain.exception.NullPublishTimeException;
import dpas.common.domain.exception.NullSignatureException;
import java.security.Signature;
import java.util.Date;

public class Post {

    private String _message;
    private Signature _signature;
    private Post[] _references; // Can be null
    private Date _publishTime; // Date and time of the post

    public Post(Signature signature, String message, Post[] references, Date publishTime) throws NullSignatureException, NullMessageException,
            NullPublishTimeException {
        checkArguments(signature, message, publishTime);
        this._signature = signature;
        this._message = message;
        this._references = references;
        this._publishTime = publishTime;
    }

    public void checkArguments(Signature signature, String message, Date publishTime) throws NullSignatureException, NullMessageException,
            NullPublishTimeException {
        if (signature == null) { throw new NullSignatureException(); }
        if (message == null) { throw new NullMessageException(); }
        if (publishTime == null) {throw new NullPublishTimeException(); }
    }

    public String getMessage() { return this._message; }
    public Signature getSignature() { return this._signature; }
    public Post[] getReferences() { return this._references; }
    //public Date getPublishTime() { return this._publishTime; }
    public String printPublishTime() { return this._publishTime.toString(); }
}
