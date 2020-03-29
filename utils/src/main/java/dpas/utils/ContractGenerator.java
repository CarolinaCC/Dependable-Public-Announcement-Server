package dpas.utils;

import com.google.protobuf.ByteString;
import dpas.grpc.contract.Contract;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ContractGenerator {

    public static Contract.ServerHello generateServerHello(PrivateKey privateKey, long seq, String sessionNonce) throws IOException, GeneralSecurityException {
        return Contract.ServerHello.newBuilder()
                .setSeq(seq)
                .setSessionNonce(sessionNonce)
                .setMac(ByteString.copyFrom(MacGenerator.generateMac(sessionNonce, seq, privateKey)))
                .build();
    }

    public static Contract.ClientHello generateClientHello(PrivateKey privateKey, PublicKey publicKey, String sessionNonce) throws IOException, GeneralSecurityException {
        return Contract.ClientHello.newBuilder()
                .setSessionNonce(sessionNonce)
                .setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                .setMac(ByteString.copyFrom(MacGenerator.generateMac(sessionNonce, publicKey, privateKey)))
                .build();
    }
}
