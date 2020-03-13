package dpas.common.domain;

import dpas.common.domain.exception.NullAnnouncementException;
import dpas.common.domain.exception.NullUserException;

import java.util.ArrayList;

public class GeneralBoard extends AnnouncementBoard {
    private ArrayList<Announcement> _posts;
    private int _sequenceNumber = 0;

    @Override
    public void post(User user, Announcement announcement) throws NullAnnouncementException, NullUserException {
        checkArguments(user, announcement);
        _posts.add(announcement);
        announcement.set_sequenceNumber(_sequenceNumber);
        _sequenceNumber++;
    }

    private void checkArguments(User user, Announcement post) throws NullUserException, NullAnnouncementException {
        if (user == null) {
            throw new NullUserException();
        }
        if (post == null) {
            throw new NullAnnouncementException();
        }
    }

}
