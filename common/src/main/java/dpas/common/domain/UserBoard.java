package dpas.common.domain;

import dpas.common.domain.exception.*;

import java.security.PublicKey;
import java.util.ArrayList;

public class UserBoard extends AnnouncementBoard {
    private ArrayList<Announcement> _posts;
    private User _owner;
    private int _sequenceNumber = 0;

    public UserBoard (User user) throws NullUserException  {
        if (user == null) throw new NullUserException();
        _owner = user;
    }

    @Override
    public void post(Announcement announcement) throws NullAnnouncementException, InvalidUserException {
        checkArguments(announcement);
        _posts.add(announcement);
        announcement.set_sequenceNumber(_sequenceNumber);
        _sequenceNumber++;
    }

    private void checkArguments( Announcement post) throws NullAnnouncementException, InvalidUserException {
        if (post == null) {
            throw new NullAnnouncementException();
        }
        if (post.getUser() != _owner) {
            throw new InvalidUserException();
        }
    }

}
