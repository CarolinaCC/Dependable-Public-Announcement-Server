package dpas.server;

import dpas.server.service.ServiceDPASImpl;
import io.grpc.BindableService;
import io.grpc.Server;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;

public class ServerDPAS {
    public static void main(String[] args) throws Exception {
        System.out.println(ServerDPAS.class.getSimpleName());

        // check arguments
        if (args.length < 1) {
            System.err.println("Argument(s) missing!");
            System.err.printf("<Usage> java port %s %n", ServerDPAS.class.getName());
            return;
        }

        final int port = Integer.parseInt(args[0]);
        final BindableService impl = (BindableService) new ServiceDPASImpl();

        //Start server
        final Server server = NettyServerBuilder
                .forPort(port)
                .addService(impl)
                .build();
        server.start();

        // Do not exit the main thread. Wait until server is terminated.
        server.awaitTermination();

    }
}
