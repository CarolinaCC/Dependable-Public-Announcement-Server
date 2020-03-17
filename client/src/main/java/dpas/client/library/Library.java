package dpas.client.library;

import dpas.common.domain.Announcement;
import dpas.grpc.contract.ServiceDPASGrpc;

import java.security.PublicKey;

public class Library {

    public ServiceDPASGrpc.ServiceDPASStub _stub;

    public void register(PublicKey publicKey, String username) {

    }

    public void post(PublicKey key, char[] message, Announcement[] a) {

    }

    public void postGeneral(PublicKey key, char[] message, Announcement[] a) {

    }

    public Announcement[] read(PublicKey publicKey) {
        return null;
    }

    public Announcement[] readGeneral(int number) {
        return null;
    }
}
