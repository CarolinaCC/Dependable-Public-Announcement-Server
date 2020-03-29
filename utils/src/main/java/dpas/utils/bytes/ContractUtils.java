package dpas.utils.bytes;

import dpas.grpc.contract.Contract;

import java.util.List;
import java.util.stream.Collectors;

public class ContractUtils {
    public static byte[] toByteArray(Contract.SafePostRequest request) {
        long seq = request.getSeq();
        byte[] nonce = request.getSessionNonce().getBytes();
        byte[] pubKey = request.getPublicKey().toByteArray();
        byte[] message = request.getMessage().toByteArray();
        byte[] signature = request.getSignature().toByteArray();
        List<byte[]> refs = request.getReferencesList().stream().map(String::getBytes).collect(Collectors.toList());
        return null;
    }
}
