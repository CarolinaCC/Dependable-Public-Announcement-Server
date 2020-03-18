package dpas.server;

import dpas.server.persistence.PersistenceManager;
import io.grpc.BindableService;
import io.grpc.Server;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;

public class ServerDPAS {

    public static Server startServer(int port, String saveFile) throws Exception {
        final BindableService impl = new PersistenceManager(saveFile).load();

        //Start server
        final Server server = NettyServerBuilder
                .forPort(port)
                .addService(impl)
                .build();

        server.start();

        return server;
    }

    public static void main(String[] args) throws Exception {
        System.out.println(ServerDPAS.class.getSimpleName());

        // check arguments
        if (args.length < 2) {
            System.err.println("Argument(s) missing!");
            System.err.printf("<Usage> java port savefile %s %n", ServerDPAS.class.getName());
            return;
        }

        Server server = startServer(Integer.parseInt(args[0]), args[1]);

        // Do not exit the main thread. Wait until server is terminated.
        server.awaitTermination();

    }
}
