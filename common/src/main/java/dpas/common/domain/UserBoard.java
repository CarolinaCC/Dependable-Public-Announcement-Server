package dpas.common.domain;

import dpas.common.domain.exception.InvalidUserException;
import dpas.common.domain.exception.NullAnnouncementException;
import dpas.common.domain.exception.NullUserException;

import java.util.ArrayList;

public class UserBoard extends AnnouncementBoard {
    private ArrayList<Announcement> _posts;
    private User _owner;
    private int _sequenceNumber = 0;

    @Override

    public void post(User user, Announcement announcement) throws NullAnnouncementException, NullUserException, InvalidUserException {
        checkArguments(user, announcement);
        _posts.add(announcement);
        announcement.set_sequenceNumber(_sequenceNumber);
        _sequenceNumber++;
    }

    public void checkArguments(User user, Announcement post) throws NullUserException, NullAnnouncementException, InvalidUserException {
        if (user == null) {
            throw new NullUserException();
        }
        if (post == null) {
            throw new NullAnnouncementException();
        }
        if (user != _owner) {
            throw new InvalidUserException();
        }
    }

}
