package dpas.utils.bytes;

import dpas.grpc.contract.Contract;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class ContractUtils {
    public static byte[] toByteArray(Contract.SafePostRequest request) throws IOException {
        byte[] seq = LongUtils.longToBytes(request.getSeq());
        byte[] nonce = request.getSessionNonce().getBytes();
        byte[] pubKey = request.getPublicKey().toByteArray();
        byte[] message = request.getMessage().toByteArray();
        byte[] signature = request.getSignature().toByteArray();
        List<byte[]> references = request.getReferencesList().stream().map(String::getBytes).collect(Collectors.toList());
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(seq);
            stream.writeBytes(nonce);
            stream.writeBytes(nonce);
            stream.writeBytes(pubKey);
            stream.writeBytes(message);
            stream.writeBytes(signature);
            stream.writeBytes(message);
            for(var ref: references) {
                stream.writeBytes(ref);
            }
            return stream.toByteArray();
        }
    }
}
