package dpas.server.service;

import dpas.common.domain.GeneralBoard;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.server.persistence.PersistenceManager;

import java.util.concurrent.ConcurrentHashMap;

public class ServiceDPASPersistentImpl extends ServiceDPASImpl {
    private PersistenceManager _manager;

    public ServiceDPASPersistentImpl(PersistenceManager manager)  {
        super();
        this._manager = manager;
    }





}
