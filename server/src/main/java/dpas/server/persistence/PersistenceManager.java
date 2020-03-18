package dpas.server.persistence;

import dpas.common.domain.Announcement;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.User;
import dpas.server.service.ServiceDPASImpl;

import java.security.PublicKey;
import java.util.concurrent.ConcurrentHashMap;

public class PersistenceManager {

    private ConcurrentHashMap<String, Announcement> _announcements;
    private ConcurrentHashMap<PublicKey, User> _users;
    private GeneralBoard _generalBoard;
    private String path;

    public PersistenceManager(ConcurrentHashMap<String, Announcement> announcements, ConcurrentHashMap<PublicKey, User> users, GeneralBoard generalBoard, String path) {
        _announcements = announcements;
        _users = users;
        _generalBoard = generalBoard;
        this.path = path;
    }

    public void save() {

    }

    public ServiceDPASImpl load() {

    }
}
