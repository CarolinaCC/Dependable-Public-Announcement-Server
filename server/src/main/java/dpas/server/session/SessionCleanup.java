package dpas.server.session;

public class SessionCleanup implements Runnable {
    private SessionManager _manager;
    private long _frequency;

    public SessionCleanup(SessionManager manager, long frequency) {
        _manager = manager;
        _frequency = frequency;
    }

    @Override
    public void run() {
        while (true) {
            sleep();
            _manager.cleanup();
            }
    }

    private void sleep() {
        try {
            Thread.sleep(_frequency);
        } catch (InterruptedException e) {
            System.out.println("Warning: Session Cleanup Thread was interrupted and started earlier");
        }
    }
}
