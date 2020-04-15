package dpas.utils.auth;

import io.grpc.StatusRuntimeException;

import java.security.PublicKey;
import java.util.Arrays;

public class ErrorVerifier {

    public static boolean verifyError(StatusRuntimeException e, byte[] request, PublicKey key) {
        if (e.getTrailers() == null) {
            return false;
        }
        var trailers = e.getTrailers();

        if (trailers.get(ErrorGenerator.contentKey) == null) {
            return false;
        }

        if (trailers.get(ErrorGenerator.macKey) == null) {
            return false;
        }

        if (!Arrays.equals(request, trailers.get(ErrorGenerator.contentKey))) {
            return false;
        }

        return MacVerifier.verifyMac(key, e);
    }

    public static boolean verifyError(Throwable t, byte[] request, PublicKey key) {
        if (!(t instanceof  StatusRuntimeException)) {
            return false;
        }
        return verifyError((StatusRuntimeException) t, request, key);
    }
}
