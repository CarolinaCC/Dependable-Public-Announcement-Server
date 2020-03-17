package dpas.common.domain;

import dpas.common.domain.exception.NullAnnouncementException;
import dpas.common.domain.exception.NullUserException;

public class GeneralBoard extends AnnouncementBoard {
    private int _sequenceNumber = 0;

    @Override
    public void post(Announcement announcement) throws NullAnnouncementException, NullUserException {
        if (announcement == null) {
            throw new NullAnnouncementException();
        }
        _posts.add(announcement);
        announcement.set_sequenceNumber(_sequenceNumber);
        _sequenceNumber++;
    }



}
