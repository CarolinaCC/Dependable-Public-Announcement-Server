package dpas.server;

import dpas.common.domain.exception.*;
import dpas.server.persistence.PersistenceManager;
import io.grpc.BindableService;
import io.grpc.Server;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

public class ServerDPAS {

    public static Server startServer(int port, String saveFile) {
        try {
            final BindableService impl = new PersistenceManager(saveFile).load();
            final Server server = NettyServerBuilder
                    .forPort(port)
                    .addService(impl)
                    .build();

            server.start();
            return server;
        } catch (Exception e) {
            System.out.println("Error Initializing server: Invalid State Load");
            System.exit(1);
        }
        //Code never reaches here
        return null;
    }

    public static void main(String[] args) throws Exception {
        System.out.println(ServerDPAS.class.getSimpleName());

        // check arguments
        if (args.length < 2) {
            System.err.println("Argument(s) missing!");
            System.err.printf("<Usage> java port saveFile %s %n", ServerDPAS.class.getName());
            return;
        }

        Server server = startServer(Integer.parseInt(args[0]), args[1]);

        // Do not exit the main thread. Wait until server is terminated.
        server.awaitTermination();

    }
}
