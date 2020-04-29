package dpas.utils.auth;

import dpas.grpc.contract.Contract;
import dpas.utils.Constants;
import io.grpc.Metadata;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.apache.commons.lang3.ArrayUtils;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;

public final class ErrorGenerator {

    public static final Metadata.Key<byte[]> contentKey = Metadata.Key.of(Constants.REQ_KEY, Metadata.BINARY_BYTE_MARSHALLER);
    public static final Metadata.Key<byte[]> macKey = Metadata.Key.of(Constants.MAC_KEY, Metadata.BINARY_BYTE_MARSHALLER);

    private ErrorGenerator() {}

    public static StatusRuntimeException generate(Status status, String message, Contract.RegisterRequest request, PrivateKey privKey) {
        var statusException = status.withDescription(message).asRuntimeException(new Metadata());
        return fillMetadata(request.getMac().toByteArray(), privKey, statusException);
    }

    public static StatusRuntimeException generate(Status status, String message, Contract.ReadRequest request, PrivateKey privKey) {
        var statusException = status.withDescription(message).asRuntimeException(new Metadata());
        return fillMetadata(request.getNonce().getBytes(), privKey, statusException);
    }

    public static StatusRuntimeException generate(Status status, String message, Contract.EchoRegister request, PrivateKey privKey) {
        var statusException = status.withDescription(message).asRuntimeException(new Metadata());
        return fillMetadata(request.getMac().toByteArray(), privKey, statusException);
    }

    public static StatusRuntimeException generate(Status status, String message, Contract.EchoAnnouncement request, PrivateKey privKey) {
        var statusException = status.withDescription(message).asRuntimeException(new Metadata());
        return fillMetadata(request.getMac().toByteArray(), privKey, statusException);
    }

    public static StatusRuntimeException generate(Status status, String message, Contract.ReadyAnnouncement request, PrivateKey privKey) {
        var statusException = status.withDescription(message).asRuntimeException(new Metadata());
        return fillMetadata(request.getMac().toByteArray(), privKey, statusException);
    }

    public static StatusRuntimeException generate(Status status, String message, Contract.ReadyRegister request, PrivateKey privKey) {
        var statusException = status.withDescription(message).asRuntimeException(new Metadata());
        return fillMetadata(request.getMac().toByteArray(), privKey, statusException);
    }

    public static StatusRuntimeException generate(Status status, String message, Contract.Announcement request, PrivateKey privKey) {
        var statusException = status.withDescription(message).asRuntimeException(new Metadata());
        return fillMetadata(request.getSignature().toByteArray(), privKey, statusException);
    }

    private static StatusRuntimeException fillMetadata(byte[] content, PrivateKey privKey, StatusRuntimeException e) {
        var toSign = ArrayUtils.addAll(content, e.getMessage().getBytes());
        Metadata metadata = e.getTrailers();
        metadata.put(contentKey, content);
        try {
            metadata.put(macKey, MacGenerator.generateMac(toSign, privKey));
        } catch (GeneralSecurityException ex) {
            //Should never happen
            //leave the mac empty
            metadata.put(macKey, new byte[]{});
        }
        return e;
    }
}
